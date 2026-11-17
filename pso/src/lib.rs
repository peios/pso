//! Peios Signed Objects for an ordinary system: keys, issuing certificates,
//! leaves and revocations, reading the trust store's directories, and the
//! places a file carries its bundle.
//!
//! Verification itself, and everything the specification says about the
//! objects, is in `pso_core`. Section references such as §7.9 are to PGSS.

pub mod hex;
pub mod issue;
pub mod keys;
pub mod place;
pub mod store;

pub use pso_core as core;
