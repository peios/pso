//! Keys: making one, keeping it in a file, and signing with it.
//!
//! A secret key is kept as its 32-byte seed, from which the whole key is
//! made again each time. Both kinds of key file are one line of text:
//!
//! ```text
//! pso-secret-key ml-dsa-65 <seed in hexadecimal>
//! pso-public-key ml-dsa-65 <key in hexadecimal>
//! ```

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use ml_dsa::{MlDsa65, MlDsa87, SigningKey};

use pso_core::{Crypto, Key, KeyType, RustCrypto};

use crate::hex;

const SECRET_LABEL: &str = "pso-secret-key";
const PUBLIC_LABEL: &str = "pso-public-key";
const SEED_LEN: usize = 32;
/// Only the owner reads or writes a secret key.
const SECRET_MODE: u32 = 0o600;
/// Where a seed's randomness comes from.
const RANDOM_SOURCE: &str = "/dev/urandom";

/// The key type `name` gives, as a key file and the command line write it.
pub fn key_type_from_name(name: &str) -> Result<KeyType> {
    [KeyType::MlDsa65, KeyType::MlDsa87]
        .into_iter()
        .find(|key_type| key_type.name() == name)
        .ok_or_else(|| anyhow!("unknown key type {name}: use ml-dsa-65 or ml-dsa-87"))
}

/// A secret key, which signs.
pub struct SecretKey {
    key_type: KeyType,
    seed: [u8; SEED_LEN],
}

impl SecretKey {
    /// A new key of `key_type`, from the system's randomness.
    pub fn generate(key_type: KeyType) -> Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        fs::File::open(RANDOM_SOURCE)
            .and_then(|mut source| source.read_exact(&mut seed))
            .with_context(|| format!("reading {RANDOM_SOURCE}"))?;
        Ok(Self { key_type, seed })
    }

    /// The key that `seed` makes. The same seed always makes the same key.
    pub fn from_seed(key_type: KeyType, seed: [u8; SEED_LEN]) -> Self {
        Self { key_type, seed }
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// The public key.
    pub fn public(&self) -> Key {
        let bytes = match self.key_type {
            KeyType::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&self.seed.into())
                .expanded_key()
                .verifying_key()
                .encode()
                .to_vec(),
            KeyType::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&self.seed.into())
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
            KeyType::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&self.seed.into())
                .expanded_key()
                .sign_deterministic(message, &[])
                .map(|signature| signature.encode().to_vec()),
            KeyType::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&self.seed.into())
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

    /// Reads the secret key file at `path`. No error tells of what the
    /// file holds.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .map_err(|_| anyhow!("{}: cannot read the key", path.display()))?;
        let (key_type, seed) = parse_line(&text, SECRET_LABEL)
            .map_err(|_| anyhow!("{}: not a secret key file", path.display()))?;
        let seed = <[u8; SEED_LEN]>::try_from(seed)
            .map_err(|_| anyhow!("{}: not a secret key file", path.display()))?;
        Ok(Self { key_type, seed })
    }

    /// Writes the key to a new file at `path`, which only its owner can
    /// read. A file already there is never replaced.
    pub fn save(&self, path: &Path) -> Result<()> {
        let line = format!(
            "{SECRET_LABEL} {} {}\n",
            self.key_type.name(),
            hex::encode(&self.seed)
        );
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_MODE)
            .open(path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .with_context(|| format!("writing {}", path.display()))
    }
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
    let (key_type, bytes) = parse_line(&text, PUBLIC_LABEL)
        .with_context(|| format!("{}: not a public key file", path.display()))?;
    Key::new(key_type, bytes).map_err(|_| anyhow!("{}: a key of the wrong length", path.display()))
}

fn parse_line(text: &str, label: &str) -> Result<(KeyType, Vec<u8>)> {
    let mut words = text.split_whitespace();
    let (Some(found), Some(key_type), Some(body), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        bail!("expected three words");
    };
    if found != label {
        bail!("expected {label}");
    }
    Ok((key_type_from_name(key_type)?, hex::decode(body)?))
}
