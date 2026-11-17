//! The trust store's directories (§7.10), read as a store keeper reads
//! them, and the directory a verifier finds intermediaries in (§7.11).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use pso_core::{
    Certificate, Crypto, Distrust, Hash, Key, Lookup, MAX_FOUND_CERTIFICATE_LEN, Revocation, Role,
    RustCrypto, TargetType, TrustStore,
};

use crate::hex;

/// Top-levels that packages ship.
pub const PACKAGE_TOP_LEVELS: &str = "usr/share/pso/toplevel";
/// Revocations that packages ship.
pub const PACKAGE_REVOCATIONS: &str = "usr/share/pso/revocation";
/// Intermediaries that packages ship.
pub const PACKAGE_INTERMEDIARIES: &str = "usr/share/pso/intermediate";
/// Top-levels the administrator trusts.
pub const LOCAL_TOP_LEVELS: &str = "lcl/policy/pso/toplevel";
/// Revocations the store keeper has accepted.
pub const LOCAL_REVOCATIONS: &str = "lcl/policy/pso/revocation";
/// Distrust entries.
pub const LOCAL_DISTRUST: &str = "lcl/policy/pso/distrust";

/// A trust store as read from a system's directories.
#[derive(Debug, Default)]
pub struct LoadedStore {
    pub store: TrustStore,
    /// Top-levels a package ships that no root signed and the administrator
    /// has not approved.
    pub quarantined: Vec<Hash>,
    /// Entries that were passed over, each with why.
    pub ignored: Vec<(PathBuf, String)>,
}

/// Reads the trust store of the system whose root directory is `root`, for
/// a verifier that holds `roots`.
///
/// `root` need not be the running system's: an approval link is resolved
/// against it, not against `/`.
pub fn load(root: &Path, roots: &[Key]) -> Result<LoadedStore> {
    let crypto = RustCrypto;
    let mut loaded = LoadedStore::default();

    for (path, hash, bytes) in entries(&root.join(LOCAL_DISTRUST), &mut loaded.ignored)? {
        match Distrust::decode(&bytes) {
            Ok(entry) if entry.target == hash => loaded.store.distrust.push(entry),
            Ok(_) => loaded
                .ignored
                .push((path, "is not named by the hash it distrusts".into())),
            Err(error) => loaded
                .ignored
                .push((path, format!("is malformed: {error:?}"))),
        }
    }
    let distrusted = |hash: &Hash, store: &TrustStore| {
        store
            .distrust
            .iter()
            .any(|d| d.target_type == TargetType::Certificate && &d.target == hash)
    };

    for directory in [PACKAGE_REVOCATIONS, LOCAL_REVOCATIONS] {
        for (path, hash, bytes) in entries(&root.join(directory), &mut loaded.ignored)? {
            match Revocation::decode(&bytes) {
                Ok(revocation) if crypto.sha512(&[&bytes]) == hash => {
                    if !loaded.store.revocations.contains(&revocation) {
                        loaded.store.revocations.push(revocation);
                    }
                }
                Ok(_) => loaded
                    .ignored
                    .push((path, "is not named by its hash".into())),
                Err(error) => loaded
                    .ignored
                    .push((path, format!("is malformed: {error:?}"))),
            }
        }
    }

    // A package's top-level is enabled only if a root this verifier holds
    // signed it. Any other waits for the administrator's approval.
    for (path, hash, bytes) in entries(&root.join(PACKAGE_TOP_LEVELS), &mut loaded.ignored)? {
        let Some(certificate) = top_level(&path, &hash, &bytes, &mut loaded.ignored) else {
            continue;
        };
        let signer = roots
            .iter()
            .find(|r| r.hash(&crypto) == certificate.body.issuer);
        let rooted = signer.is_some_and(|root| {
            crypto.verify(root, certificate.signed_bytes(), certificate.signature()) == Ok(true)
        });
        if !rooted {
            loaded.quarantined.push(hash);
        } else if !distrusted(&hash, &loaded.store) {
            enable(&mut loaded, &path, &bytes);
        }
    }

    // Everything the administrator's directory holds is enabled: a file is
    // a certificate they supplied, and a link approves one a package ships.
    for (path, hash, bytes) in entries(&root.join(LOCAL_TOP_LEVELS), &mut loaded.ignored)? {
        if top_level(&path, &hash, &bytes, &mut loaded.ignored).is_none() {
            continue;
        }
        loaded
            .quarantined
            .retain(|quarantined| quarantined != &hash);
        if !distrusted(&hash, &loaded.store) {
            enable(&mut loaded, &path, &bytes);
        }
    }
    Ok(loaded)
}

fn enable(loaded: &mut LoadedStore, path: &Path, bytes: &[u8]) {
    if let Err(error) = loaded.store.enable(&RustCrypto, bytes) {
        loaded
            .ignored
            .push((path.into(), format!("is malformed: {error:?}")));
    }
}

/// The top-level certificate in `bytes`, or `None` with the reason recorded.
fn top_level(
    path: &Path,
    hash: &Hash,
    bytes: &[u8],
    ignored: &mut Vec<(PathBuf, String)>,
) -> Option<Certificate> {
    if &RustCrypto.sha512(&[bytes]) != hash {
        ignored.push((path.into(), "is not named by its hash".into()));
        return None;
    }
    match Certificate::decode(bytes) {
        Ok(certificate) if certificate.body.role == Role::TopLevel => Some(certificate),
        Ok(_) => {
            ignored.push((path.into(), "is not a top-level".into()));
            None
        }
        Err(error) => {
            ignored.push((path.into(), format!("is malformed: {error:?}")));
            None
        }
    }
}

/// The entries of `directory`: each one's path, the hash its name gives,
/// and its content. A directory that is absent has none.
///
/// A symbolic link is followed only if it is an approval link: one whose
/// target is the entry of the same name among the package's top-levels,
/// which is resolved beside `directory`'s own root. A link whose target is
/// absent is an approval of a top-level its package has withdrawn, and is
/// passed over without comment.
fn entries(
    directory: &Path,
    ignored: &mut Vec<(PathBuf, String)>,
) -> Result<Vec<(PathBuf, Hash, Vec<u8>)>> {
    let listing = match fs::read_dir(directory) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", directory.display()));
        }
    };
    let mut names: Vec<PathBuf> = listing
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading {}", directory.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .collect();
    names.sort();

    let mut found = Vec::new();
    for path in names {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let Ok(hash) = hex::decode_hash(name) else {
            ignored.push((path, "is not named by a hash".into()));
            continue;
        };
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("reading {}", path.display()))?;
        let source = if metadata.file_type().is_symlink() {
            match approved_target(directory, &path, name) {
                Some(target) if target.is_file() => target,
                Some(_) => continue,
                None => {
                    ignored.push((
                        path,
                        "is a link to something other than its package's top-level".into(),
                    ));
                    continue;
                }
            }
        } else if metadata.is_file() {
            path.clone()
        } else {
            ignored.push((path, "is not a file".into()));
            continue;
        };
        let bytes = fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
        found.push((path, hash, bytes));
    }
    Ok(found)
}

/// Where the approval link at `path` leads, resolved against the root that
/// `directory` is under, or `None` if it is not an approval link.
fn approved_target(directory: &Path, path: &Path, name: &str) -> Option<PathBuf> {
    let expected = Path::new("/").join(PACKAGE_TOP_LEVELS).join(name);
    if fs::read_link(path).ok()? != expected {
        return None;
    }
    let root = directory.to_str()?.strip_suffix(LOCAL_TOP_LEVELS)?;
    Some(Path::new(root).join(PACKAGE_TOP_LEVELS).join(name))
}

/// Finds intermediaries in a directory, each in a file named by its object
/// hash (§7.11).
pub struct DirectoryLookup {
    directory: PathBuf,
}

impl DirectoryLookup {
    /// Looks in `directory`, which is `share/pso/intermediate` beneath the
    /// `/usr` of whoever the verifier is working for.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }
}

impl Lookup for DirectoryLookup {
    fn intermediary(&mut self, hash: &Hash) -> Option<Vec<u8>> {
        let path = self.directory.join(hex::encode(hash));
        // Only a regular file is read, and a link is not followed: the
        // directory belongs to whoever asked, and can hold anything.
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_FOUND_CERTIFICATE_LEN as u64 {
            return None;
        }
        fs::read(&path).ok()
    }
}
