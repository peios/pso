//! Peios Signed Objects, as PGSS chapter 7 specifies them: the objects and
//! their encoding, warrants and how they narrow, and verification of a
//! bundle against roots and a trust store.
//!
//! This crate does no I/O. A caller reads the bundle, hashes the file, and
//! supplies the trust store and a way to find intermediaries; `pso` does
//! that for an ordinary system.
//!
//! Section references such as §7.5 are to PGSS.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod crypto;
mod object;
mod verify;
mod warrant;
mod wire;

#[cfg(feature = "rustcrypto")]
pub use crypto::RustCrypto;
pub use crypto::{Crypto, HASH_LEN, Hash, Key, KeyType, Unavailable};
pub use object::{
    Bundle, Certificate, CertificateBody, Distrust, FORMAT_VERSION, HashForm, Kind, Leaf, LeafBody,
    MAX_BUNDLE_CERTIFICATES, MAX_BUNDLE_LEN, MAX_FOUND_CERTIFICATE_LEN, MAX_INTERMEDIARIES,
    MAX_STORE_IMAGE_LEN, Malformed, Revocation, RevocationBody, Role, TargetType,
    decode_store_image, encode_bundle, encode_store_image,
};
pub use verify::{
    ImageError, Invalid, Lookup, NoLookup, Outcome, Refusal, Skipped, TrustStore, Verified,
    Verifier, check_narrowing,
};
pub use warrant::{DELEGATE, NAME, REVOKE, Warrant, WarrantType, name_is_within, valid_leaf_name};
