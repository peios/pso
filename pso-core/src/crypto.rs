//! The hash and signature algorithms (§7.4), behind a trait so that a
//! verifier can bring its own.

use alloc::vec::Vec;

use crate::object::Malformed;

/// The length of every hash: SHA-512.
pub const HASH_LEN: usize = 64;

/// A SHA-512 hash, as raw bytes.
pub type Hash = [u8; HASH_LEN];

/// A signature could not be checked at all: the algorithm is missing or
/// the implementation failed. This is never "the signature is wrong".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

/// The algorithm of a key, and so of every signature made with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    MlDsa65,
    MlDsa87,
}

impl KeyType {
    pub fn from_byte(byte: u8) -> Result<Self, Malformed> {
        match byte {
            0x01 => Ok(Self::MlDsa65),
            0x02 => Ok(Self::MlDsa87),
            _ => Err(Malformed::UnknownKeyType),
        }
    }

    pub fn byte(self) -> u8 {
        match self {
            Self::MlDsa65 => 0x01,
            Self::MlDsa87 => 0x02,
        }
    }

    /// The length of a raw public key of this type.
    pub fn key_len(self) -> usize {
        match self {
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// The length of a signature made with a key of this type.
    pub fn signature_len(self) -> usize {
        match self {
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }
}

/// A public key: its type and its raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub key_type: KeyType,
    pub bytes: Vec<u8>,
}

impl Key {
    /// A key of `key_type`, which `bytes` must be the right length for.
    pub fn new(key_type: KeyType, bytes: Vec<u8>) -> Result<Self, Malformed> {
        if bytes.len() != key_type.key_len() {
            return Err(Malformed::WrongKeyLength);
        }
        Ok(Self { key_type, bytes })
    }

    /// The key hash: SHA-512 of the key type byte and then the key.
    pub fn hash(&self, crypto: &dyn Crypto) -> Hash {
        crypto.sha512(&[&[self.key_type.byte()], &self.bytes])
    }
}

/// The two algorithms PSO needs.
pub trait Crypto {
    /// SHA-512 of `parts` joined in order.
    fn sha512(&self, parts: &[&[u8]]) -> Hash;

    /// Whether `signature` is `key`'s pure ML-DSA signature of `message`
    /// with an empty context. `Err` means the check could not be made.
    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool, Unavailable>;
}

/// `Crypto` from the RustCrypto `sha2` and `ml-dsa` crates.
#[cfg(feature = "rustcrypto")]
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCrypto;

#[cfg(feature = "rustcrypto")]
impl Crypto for RustCrypto {
    fn sha512(&self, parts: &[&[u8]]) -> Hash {
        use sha2::Digest;

        let mut hasher = sha2::Sha512::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool, Unavailable> {
        use ml_dsa::{EncodedVerifyingKey, MlDsa65, MlDsa87, Signature, VerifyingKey};

        // A key or signature of the wrong length for its type cannot verify.
        macro_rules! verify_with {
            ($params:ty) => {{
                let Ok(encoded) = EncodedVerifyingKey::<$params>::try_from(key.bytes.as_slice())
                else {
                    return Ok(false);
                };
                let Ok(signature) = Signature::<$params>::try_from(signature) else {
                    return Ok(false);
                };
                VerifyingKey::<$params>::decode(&encoded).verify_with_context(
                    message,
                    &[],
                    &signature,
                )
            }};
        }
        Ok(match key.key_type {
            KeyType::MlDsa65 => verify_with!(MlDsa65),
            KeyType::MlDsa87 => verify_with!(MlDsa87),
        })
    }
}
