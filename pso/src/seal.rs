//! Sealing a secret under a passphrase, as peios-crypto does, so that a key
//! file one seals the other opens.
//!
//! A sealed blob is version 1 of this layout, which peios-crypto defines:
//!
//! | Offset | Size | Field                                              |
//! |-------:|-----:|----------------------------------------------------|
//! |      0 |    8 | magic, ASCII `PEIOSEAL`                            |
//! |      8 |    1 | format version, 1                                  |
//! |      9 |    1 | key derivation, 1 = Argon2id version 0x13          |
//! |     10 |    4 | Argon2 memory in KiB, big-endian                   |
//! |     14 |    4 | Argon2 passes, big-endian                          |
//! |     18 |    4 | Argon2 lanes, big-endian                           |
//! |     22 |    1 | salt length, 16                                    |
//! |     23 |   16 | salt                                               |
//! |     39 |    1 | cipher, 1 = AES-256-GCM                            |
//! |     40 |   12 | nonce                                              |
//! |     52 |    … | ciphertext, then the 16-byte GCM tag               |
//!
//! The 52-byte header is the cipher's associated data, so altering a
//! parameter makes opening fail rather than weakening the derivation. Each
//! seal draws a fresh salt, and so a fresh key, which makes a random nonce
//! safe.

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::keys::random_bytes;

const MAGIC: &[u8; 8] = b"PEIOSEAL";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_AES_256_GCM: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 52;

/// The parameters every seal uses: RFC 9106 §4's second recommended
/// option, 64 MiB of memory, three passes and four lanes. They are
/// peios-crypto's.
const SEAL_PARAMETERS: Argon2Parameters = Argon2Parameters {
    memory_kib: 64 * 1024,
    passes: 3,
    lanes: 4,
};

/// Upper bounds on parameters read from a blob, so that opening a hostile
/// blob can't demand gigabytes of memory or hours of work. The header is
/// authenticated, but only after the costly derivation has run. They are
/// peios-crypto's.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_PASSES: u32 = 16;
const MAX_LANES: u32 = 16;

/// Why a blob didn't open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// Not a version 1 blob, or its parameters are out of bounds.
    Malformed,
    /// The passphrase is wrong, or the blob has been altered.
    WrongPassphraseOrDamaged,
    /// The system's randomness or the derivation failed.
    Backend,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a sealed blob this tool reads",
            Self::WrongPassphraseOrDamaged => "the passphrase is wrong, or the file is damaged",
            Self::Backend => "the cryptography failed",
        })
    }
}

impl std::error::Error for SealError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Argon2Parameters {
    pub(crate) memory_kib: u32,
    pub(crate) passes: u32,
    pub(crate) lanes: u32,
}

/// Seals `secret` under `passphrase`, which the caller has normalised and
/// held to whatever strength rule applies.
pub fn seal(secret: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, SealError> {
    seal_with(secret, passphrase, SEAL_PARAMETERS)
}

pub(crate) fn seal_with(
    secret: &[u8],
    passphrase: &[u8],
    parameters: Argon2Parameters,
) -> Result<Vec<u8>, SealError> {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt).map_err(|_| SealError::Backend)?;
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce).map_err(|_| SealError::Backend)?;

    let mut blob = Vec::with_capacity(HEADER_LEN + secret.len() + TAG_LEN);
    blob.extend_from_slice(MAGIC);
    blob.push(FORMAT_VERSION);
    blob.push(KDF_ARGON2ID);
    blob.extend_from_slice(&parameters.memory_kib.to_be_bytes());
    blob.extend_from_slice(&parameters.passes.to_be_bytes());
    blob.extend_from_slice(&parameters.lanes.to_be_bytes());
    blob.push(SALT_LEN as u8);
    blob.extend_from_slice(&salt);
    blob.push(CIPHER_AES_256_GCM);
    blob.extend_from_slice(&nonce);

    let cipher = cipher(passphrase, &salt, parameters)?;
    let payload = Payload {
        msg: secret,
        aad: &blob[..HEADER_LEN],
    };
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| SealError::Backend)?;
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Opens a blob sealed by [`seal`] or by peios-crypto.
pub fn open(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let header = Header::parse(blob)?;
    let cipher = cipher(passphrase, &header.salt, header.parameters)?;
    let payload = Payload {
        msg: &blob[HEADER_LEN..],
        aad: &blob[..HEADER_LEN],
    };
    cipher
        .decrypt(Nonce::from_slice(&header.nonce), payload)
        .map(Zeroizing::new)
        .map_err(|_| SealError::WrongPassphraseOrDamaged)
}

/// Whether `blob` starts as a sealed blob does. Says nothing of whether it
/// opens.
pub fn looks_sealed(blob: &[u8]) -> bool {
    blob.starts_with(MAGIC)
}

struct Header {
    parameters: Argon2Parameters,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn parse(blob: &[u8]) -> Result<Self, SealError> {
        if blob.len() < HEADER_LEN + TAG_LEN || &blob[..8] != MAGIC {
            return Err(SealError::Malformed);
        }
        if blob[8] != FORMAT_VERSION || blob[9] != KDF_ARGON2ID || blob[39] != CIPHER_AES_256_GCM {
            return Err(SealError::Malformed);
        }
        if usize::from(blob[22]) != SALT_LEN {
            return Err(SealError::Malformed);
        }
        let word = |at: usize| u32::from_be_bytes(blob[at..at + 4].try_into().expect("4 bytes"));
        let parameters = Argon2Parameters {
            memory_kib: word(10),
            passes: word(14),
            lanes: word(18),
        };
        let within_bounds = parameters.memory_kib <= MAX_MEMORY_KIB
            && (1..=MAX_PASSES).contains(&parameters.passes)
            && (1..=MAX_LANES).contains(&parameters.lanes);
        if !within_bounds {
            return Err(SealError::Malformed);
        }
        Ok(Self {
            parameters,
            salt: blob[23..39].try_into().expect("16 bytes"),
            nonce: blob[40..HEADER_LEN].try_into().expect("12 bytes"),
        })
    }
}

fn cipher(
    passphrase: &[u8],
    salt: &[u8],
    parameters: Argon2Parameters,
) -> Result<Aes256Gcm, SealError> {
    let argon2_parameters = argon2::Params::new(
        parameters.memory_kib,
        parameters.passes,
        parameters.lanes,
        Some(KEY_LEN),
    )
    .map_err(|_| SealError::Malformed)?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_parameters,
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| SealError::Backend)?;
    Aes256Gcm::new_from_slice(&*key).map_err(|_| SealError::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small parameters keep these tests fast; the vectors use the real ones.
    const TEST_PARAMETERS: Argon2Parameters = Argon2Parameters {
        memory_kib: 64,
        passes: 1,
        lanes: 1,
    };

    #[test]
    fn a_sealed_secret_opens_with_its_passphrase_and_no_other() {
        let blob = seal_with(b"root key", b"correct horse", TEST_PARAMETERS).unwrap();
        assert_eq!(&*open(&blob, b"correct horse").unwrap(), b"root key");
        assert_eq!(
            open(&blob, b"battery staple"),
            Err(SealError::WrongPassphraseOrDamaged)
        );
    }

    #[test]
    fn the_header_records_the_format_and_parameters() {
        let blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        assert_eq!(&blob[..8], b"PEIOSEAL");
        assert_eq!(blob[8..10], [FORMAT_VERSION, KDF_ARGON2ID]);
        assert_eq!(blob[10..14], 64u32.to_be_bytes());
        assert_eq!(blob[14..18], 1u32.to_be_bytes());
        assert_eq!(blob[18..22], 1u32.to_be_bytes());
        assert_eq!(blob[22], 16);
        assert_eq!(blob[39], CIPHER_AES_256_GCM);
        assert_eq!(blob.len(), HEADER_LEN + b"root key".len() + TAG_LEN);
    }

    #[test]
    fn altered_parameters_or_ciphertext_are_refused() {
        let blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        let mut weaker = blob.clone();
        weaker[13] = 32;
        assert_eq!(
            open(&weaker, b"pass"),
            Err(SealError::WrongPassphraseOrDamaged)
        );
        let mut flipped = blob;
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            open(&flipped, b"pass"),
            Err(SealError::WrongPassphraseOrDamaged)
        );
    }

    #[test]
    fn unknown_formats_and_hostile_parameters_are_refused_before_deriving() {
        let blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        let mut version = blob.clone();
        version[8] = 2;
        let mut memory = blob.clone();
        memory[10..14].copy_from_slice(&(MAX_MEMORY_KIB + 1).to_be_bytes());
        let mut passes = blob.clone();
        passes[14..18].copy_from_slice(&0u32.to_be_bytes());
        let mut salt = blob.clone();
        salt[22] = 15;
        for hostile in [
            &version,
            &memory,
            &passes,
            &salt,
            &blob[..HEADER_LEN].to_vec(),
        ] {
            assert_eq!(open(hostile, b"pass"), Err(SealError::Malformed));
        }
    }

    #[test]
    fn every_seal_uses_a_fresh_salt_and_nonce() {
        let first = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        let second = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        assert_ne!(first[23..39], second[23..39]);
        assert_ne!(first[40..52], second[40..52]);
    }
}
