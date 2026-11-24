//! Keys: making one, keeping it in a file, and signing with it.
//!
//! A secret key is kept as its 32-byte seed, from which the whole key is
//! made again each time. Every kind of key file is one line of text:
//!
//! ```text
//! pso-secret-key ml-dsa-65 <seed in hexadecimal>
//! pso-sealed-key ml-dsa-65 <sealed blob in hexadecimal>
//! pso-public-key ml-dsa-65 <key in hexadecimal>
//! ```
//!
//! A sealed key's blob is peios-crypto's `PEIOSEAL` format (see
//! [`crate::seal`]) over the key type's byte followed by the seed. The type
//! on the line is a hint, for saying what a file holds without its
//! passphrase; the sealed byte is what counts, and the two must agree.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ml_dsa::{MlDsa65, MlDsa87, SigningKey};

use pso_core::{Crypto, Key, KeyType, RustCrypto};

use crate::hex;
use crate::passphrase::{NewPassphrase, Source};
use crate::seal;

const SECRET_LABEL: &str = "pso-secret-key";
const SEALED_LABEL: &str = "pso-sealed-key";
const PUBLIC_LABEL: &str = "pso-public-key";
const SEED_LEN: usize = 32;
/// Only the owner reads or writes a secret key.
const SECRET_MODE: u32 = 0o600;
/// Where a seed's randomness comes from.
const RANDOM_SOURCE: &str = "/dev/urandom";

/// Fills `bytes` from the system's randomness.
pub(crate) fn random_bytes(bytes: &mut [u8]) -> std::io::Result<()> {
    fs::File::open(RANDOM_SOURCE).and_then(|mut source| source.read_exact(bytes))
}

/// The key type `name` gives, as a key file and the command line write it.
pub fn key_type_from_name(name: &str) -> Result<KeyType> {
    [KeyType::MlDsa65, KeyType::MlDsa87]
        .into_iter()
        .find(|key_type| key_type.name() == name)
        .ok_or_else(|| anyhow!("unknown key type {name}: use ml-dsa-65 or ml-dsa-87"))
}

/// A secret key, which signs. Its seed is wiped when it is dropped.
pub struct SecretKey {
    key_type: KeyType,
    seed: zeroize::Zeroizing<[u8; SEED_LEN]>,
}

impl SecretKey {
    /// A new key of `key_type`, from the system's randomness.
    pub fn generate(key_type: KeyType) -> Result<Self> {
        let mut seed = zeroize::Zeroizing::new([0u8; SEED_LEN]);
        random_bytes(&mut *seed).with_context(|| format!("reading {RANDOM_SOURCE}"))?;
        Ok(Self { key_type, seed })
    }

    /// The key that `seed` makes. The same seed always makes the same key.
    pub fn from_seed(key_type: KeyType, seed: [u8; SEED_LEN]) -> Self {
        Self {
            key_type,
            seed: zeroize::Zeroizing::new(seed),
        }
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// The public key.
    pub fn public(&self) -> Key {
        let bytes = match self.key_type {
            KeyType::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&(*self.seed).into())
                .expanded_key()
                .verifying_key()
                .encode()
                .to_vec(),
            KeyType::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&(*self.seed).into())
                .expanded_key()
                .verifying_key()
                .encode()
                .to_vec(),
        };
        Key::new(self.key_type, bytes).expect("a key has the length its type gives")
    }

    /// The signature of `message`: pure ML-DSA with an empty context
    /// (§7.4). It is deterministic, and is checked before it is returned.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = match self.key_type {
            KeyType::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&(*self.seed).into())
                .expanded_key()
                .sign_deterministic(message, &[])
                .map(|signature| signature.encode().to_vec()),
            KeyType::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&(*self.seed).into())
                .expanded_key()
                .sign_deterministic(message, &[])
                .map(|signature| signature.encode().to_vec()),
        }
        .map_err(|_| anyhow!("cannot sign"))?;
        if RustCrypto.verify(&self.public(), message, &signature) != Ok(true) {
            bail!("the signature made does not verify");
        }
        Ok(signature)
    }

    /// Reads the plain secret key file at `path`. A sealed file is refused:
    /// open it with [`KeyFile`]. No error tells of what the file holds.
    pub fn load(path: &Path) -> Result<Self> {
        KeyFile::read(path)?.open_plain()
    }

    /// Reads the secret key file at `path`, asking `source` for its
    /// passphrase if it is sealed, and only then.
    pub fn load_with(path: &Path, source: &Source) -> Result<Self> {
        KeyFile::read(path)?.open(source)
    }

    /// Writes the key in the clear to a new file at `path`, which only its
    /// owner can read. A file already there is never replaced.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_new(path, self.plain_line().as_bytes())
    }

    /// Writes the key sealed under `passphrase` to a new file at `path`,
    /// which only its owner can read. A file already there is never
    /// replaced.
    pub fn save_sealed(&self, path: &Path, passphrase: &NewPassphrase) -> Result<()> {
        write_new(path, self.sealed_line(passphrase)?.as_bytes())
    }

    /// Replaces the key file at `path` with this key sealed under
    /// `passphrase`. The new file is written beside it and renamed over it,
    /// so a failure leaves the old file as it was. The old file's bytes are
    /// not scrubbed from the disk.
    pub fn replace_sealed(&self, path: &Path, passphrase: &NewPassphrase) -> Result<()> {
        write_replacing(path, self.sealed_line(passphrase)?.as_bytes())
    }

    fn plain_line(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!(
            "{SECRET_LABEL} {} {}\n",
            self.key_type.name(),
            hex::encode(&*self.seed)
        ))
    }

    fn sealed_line(&self, passphrase: &NewPassphrase) -> Result<String> {
        let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(1 + SEED_LEN));
        plaintext.push(self.key_type.byte());
        plaintext.extend_from_slice(&*self.seed);
        let blob = seal::seal(&plaintext, passphrase.bytes()).context("sealing the key")?;
        Ok(format!(
            "{SEALED_LABEL} {} {}\n",
            self.key_type.name(),
            hex::encode(&blob)
        ))
    }
}

/// A secret key file as read, before any passphrase is asked for.
pub enum KeyFile {
    Plain {
        path: PathBuf,
        key: SecretKey,
    },
    Sealed {
        path: PathBuf,
        key_type: KeyType,
        blob: Vec<u8>,
    },
}

impl KeyFile {
    /// Reads the secret key file at `path`. No error tells of what the file
    /// holds.
    pub fn read(path: &Path) -> Result<Self> {
        let text = zeroize::Zeroizing::new(
            fs::read_to_string(path)
                .map_err(|_| anyhow!("{}: cannot read the key", path.display()))?,
        );
        let not_a_key = || anyhow!("{}: not a secret key file", path.display());
        let (label, key_type, body) = split_line(&text).map_err(|_| not_a_key())?;
        let path = path.to_owned();
        match label {
            SECRET_LABEL => {
                let seed = zeroize::Zeroizing::new(hex::decode(body).map_err(|_| not_a_key())?);
                let seed = <[u8; SEED_LEN]>::try_from(seed.as_slice()).map_err(|_| not_a_key())?;
                Ok(Self::Plain {
                    path,
                    key: SecretKey::from_seed(key_type, seed),
                })
            }
            SEALED_LABEL => {
                let blob = hex::decode(body).map_err(|_| not_a_key())?;
                if !seal::looks_sealed(&blob) {
                    return Err(not_a_key());
                }
                Ok(Self::Sealed {
                    path,
                    key_type,
                    blob,
                })
            }
            _ => Err(not_a_key()),
        }
    }

    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed { .. })
    }

    /// The key's type, which for a sealed file is the line's claim until
    /// it is opened.
    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Plain { key, .. } => key.key_type(),
            Self::Sealed { key_type, .. } => *key_type,
        }
    }

    /// The key, asking `source` for the passphrase if the file is sealed.
    pub fn open(self, source: &Source) -> Result<SecretKey> {
        match self {
            Self::Plain { key, .. } => Ok(key),
            Self::Sealed {
                path,
                key_type,
                blob,
            } => {
                let passphrase = source.read(&path.display().to_string())?;
                let plaintext = seal::open(&blob, passphrase.bytes())
                    .map_err(|error| anyhow!("{}: {error}", path.display()))?;
                let malformed = || anyhow!("{}: the sealed key is malformed", path.display());
                let (&type_byte, seed) = plaintext.split_first().ok_or_else(malformed)?;
                let sealed_type = KeyType::from_byte(type_byte).map_err(|_| malformed())?;
                if sealed_type != key_type {
                    bail!(
                        "{}: the file says {} and the sealed key is {}",
                        path.display(),
                        key_type.name(),
                        sealed_type.name()
                    );
                }
                let seed = <[u8; SEED_LEN]>::try_from(seed).map_err(|_| malformed())?;
                Ok(SecretKey::from_seed(sealed_type, seed))
            }
        }
    }

    /// The key, if the file is plain.
    pub fn open_plain(self) -> Result<SecretKey> {
        match self {
            Self::Plain { key, .. } => Ok(key),
            Self::Sealed { path, .. } => {
                bail!("{}: the key is sealed under a passphrase", path.display())
            }
        }
    }
}

/// Writes `bytes` to a new file at `path`, readable only by its owner. A
/// file already there is never replaced.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SECRET_MODE)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .with_context(|| format!("writing {}", path.display()))
}

/// Writes `bytes` to a new file beside `path`, then renames it over `path`.
fn write_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    let beside = PathBuf::from(beside);
    write_new(&beside, bytes)?;
    if let Err(error) = fs::rename(&beside, path) {
        let _ = fs::remove_file(&beside);
        return Err(error).with_context(|| format!("replacing {}", path.display()));
    }
    if let Some(directory) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("syncing {}", directory.display()))?;
    }
    Ok(())
}

/// The line a public key file holds.
pub fn format_public(key: &Key) -> String {
    format!(
        "{PUBLIC_LABEL} {} {}\n",
        key.key_type.name(),
        hex::encode(&key.bytes)
    )
}

/// Reads the public key file at `path`.
pub fn load_public(path: &Path) -> Result<Key> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_public(&text).with_context(|| format!("{}", path.display()))
}

/// The public key that `text`, the content of a public key file, holds.
pub fn parse_public(text: &str) -> Result<Key> {
    let (key_type, bytes) = parse_line(text, PUBLIC_LABEL).context("not a public key file")?;
    Key::new(key_type, bytes).map_err(|_| anyhow!("a key of the wrong length"))
}

fn parse_line(text: &str, label: &str) -> Result<(KeyType, Vec<u8>)> {
    let (found, key_type, body) = split_line(text)?;
    if found != label {
        bail!("expected {label}");
    }
    Ok((key_type, hex::decode(body)?))
}

/// The label, key type and body of a key file's line.
fn split_line(text: &str) -> Result<(&str, KeyType, &str)> {
    let mut words = text.split_whitespace();
    let (Some(label), Some(key_type), Some(body), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        bail!("expected three words");
    };
    Ok((label, key_type_from_name(key_type)?, body))
}
