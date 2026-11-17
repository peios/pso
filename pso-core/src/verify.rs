//! Verification of a bundle against roots and a trust store (§7.14).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::{Crypto, Hash, Key, Unavailable};
use crate::object::{
    Bundle, Certificate, Distrust, HashForm, Leaf, MAX_FOUND_CERTIFICATE_LEN, MAX_INTERMEDIARIES,
    Malformed, Revocation, Role, TargetType,
};
use crate::warrant::{self, DELEGATE, NAME, NarrowError, REVOKE, Warrant, name_is_within};

/// The `flags` each warrant of §7.5 must carry.
const DELEGATE_FLAGS: u8 = 0x20;
const NAME_FLAGS: u8 = 0x90;
const REVOKE_FLAGS: u8 = 0x80;

/// The trust store as a verifier holds it (§7.10): the enabled top-levels,
/// the revocations, and the distrust entries.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    top_levels: Vec<(Hash, Vec<u8>)>,
    pub revocations: Vec<Revocation>,
    pub distrust: Vec<Distrust>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables the top-level in `bytes`. The store keeper has already
    /// decided that it is to be enabled; this checks only that it is a
    /// top-level certificate.
    pub fn enable(&mut self, crypto: &dyn Crypto, bytes: &[u8]) -> Result<Hash, Malformed> {
        let certificate = Certificate::decode(bytes)?;
        if certificate.body.role != Role::TopLevel {
            return Err(Malformed::UnknownRole);
        }
        let hash = certificate.hash(crypto);
        if !self.is_enabled(&hash) {
            self.top_levels.push((hash, bytes.to_vec()));
        }
        Ok(hash)
    }

    pub fn is_enabled(&self, hash: &Hash) -> bool {
        self.top_levels.iter().any(|(enabled, _)| enabled == hash)
    }

    /// The object hashes of the enabled top-levels.
    pub fn enabled(&self) -> impl Iterator<Item = &Hash> {
        self.top_levels.iter().map(|(hash, _)| hash)
    }

    fn top_level(&self, hash: &Hash) -> Option<&[u8]> {
        self.top_levels
            .iter()
            .find(|(enabled, _)| enabled == hash)
            .map(|(_, bytes)| &bytes[..])
    }
}

/// How a verifier finds an intermediary that a bundle names and does not
/// carry (§7.11).
pub trait Lookup {
    /// The bytes filed under `hash`, if any. The verifier checks that they
    /// hash to it.
    fn intermediary(&mut self, hash: &Hash) -> Option<Vec<u8>>;
}

/// A `Lookup` that finds nothing: every chain must be carried whole, or end
/// at an enabled top-level.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoLookup;

impl Lookup for NoLookup {
    fn intermediary(&mut self, _hash: &Hash) -> Option<Vec<u8>> {
        None
    }
}

/// Why a chain is invalid. The specification reports only that it is; this
/// is for a person diagnosing one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    Malformed(Malformed),
    /// The leaf's hash form is not the one the place calls for.
    WrongHashForm,
    /// The leaf's content hash is not the file's.
    ContentMismatch,
    /// The bundle's certificates are not each the issuer of the one before.
    OutOfOrder,
    /// A certificate found by its hash does not hash to it.
    FoundHashMismatch,
    /// More intermediaries than a chain can hold.
    TooDeep,
    /// A top-level below the head of the chain.
    MisplacedTopLevel,
    /// A signature does not verify under the issuer's key.
    BadSignature,
    /// A warrant the issuer does not hold.
    WarrantAdded(String),
    /// A warrant whose flags differ from the issuer's.
    WarrantFlagsDiffer(String),
    /// A warrant wider than the issuer's.
    WarrantWidened(String),
    /// A warrant equal to the issuer's where it must be narrower.
    WarrantNotNarrowed(String),
    /// `Delegate`, `Name` or `Revoke` in a form other than §7.5 gives it.
    WarrantMisdefined(String),
    /// A certificate issued by one that holds no `Delegate`.
    NoDelegate,
    /// A leaf whose name is not within its issuer's `Name`.
    NameNotHeld,
    /// A leaf holding `Delegate`, `Name` or `Revoke`.
    ForbiddenInLeaf(String),
    /// A warrant marked Must Understand that this verifier does not know.
    NotUnderstood(String),
}

/// What refused an otherwise sound chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Revoked,
    Distrusted,
}

/// What a verifier returns about a sound chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The leaf's name.
    pub name: String,
    /// The leaf's warrants, which are the chain's effective warrants.
    pub warrants: Vec<Warrant>,
    /// The object hash of the chain's top-level.
    pub top_level: Hash,
    /// For a rooted chain, the key hash of the root.
    pub root: Option<Hash>,
}

impl Verified {
    pub fn warrant(&self, name: &str) -> Option<&Warrant> {
        warrant::find(&self.warrants, name)
    }
}

/// The result of a verification, from least to most trusted. A file with
/// no bundle is Unsigned, which a caller reports before it has anything to
/// verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Invalid(Invalid),
    /// A certificate the chain names could not be found.
    Incomplete {
        missing: Hash,
    },
    Refused(Refusal),
    /// Sound, and its top-level is not enabled.
    Consistent(Verified),
    /// Sound, and its top-level is enabled but not vouched for by a root.
    Unrooted(Verified),
    /// Sound, and its top-level is enabled and signed by a root.
    Rooted(Verified),
}

impl Outcome {
    /// The name the specification gives the result.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid",
            Self::Incomplete { .. } => "incomplete",
            Self::Refused(_) => "refused",
            Self::Consistent(_) => "consistent",
            Self::Unrooted(_) => "unrooted",
            Self::Rooted(_) => "rooted",
        }
    }

    /// What was verified, for the three results that carry it.
    pub fn verified(&self) -> Option<&Verified> {
        match self {
            Self::Consistent(verified) | Self::Unrooted(verified) | Self::Rooted(verified) => {
                Some(verified)
            }
            _ => None,
        }
    }
}

/// A step either continues or ends the verification with a result, which
/// is boxed because it is far larger than what a step usually returns.
type Step<T> = Result<T, Box<Outcome>>;

fn stop<T>(outcome: Outcome) -> Step<T> {
    Err(Box::new(outcome))
}

fn invalid<T>(invalid: Invalid) -> Step<T> {
    stop(Outcome::Invalid(invalid))
}

impl From<Malformed> for Box<Outcome> {
    fn from(malformed: Malformed) -> Self {
        Box::new(Outcome::Invalid(Invalid::Malformed(malformed)))
    }
}

/// A verifier: the roots it was built with, the trust store, and the names
/// of the warrants its callers act on.
pub struct Verifier<'a> {
    pub crypto: &'a dyn Crypto,
    pub roots: &'a [Key],
    pub store: &'a TrustStore,
    /// Warrant names this verifier recognizes besides `Delegate`, `Name`
    /// and `Revoke`. An unrecognized warrant marked Must Understand makes a
    /// chain invalid.
    pub recognized: &'a [&'a str],
}

impl Verifier<'_> {
    /// Verifies `bundle` for a file whose content hash, in the form the
    /// place calls for, is `content_hash` (§7.14, steps 2 to 8).
    ///
    /// `Err` means a check could not be made at all, which is never a
    /// result.
    pub fn verify(
        &self,
        bundle: &[u8],
        hash_form: HashForm,
        content_hash: &Hash,
        lookup: &mut dyn Lookup,
    ) -> Result<Outcome, Unavailable> {
        match self.run(bundle, hash_form, content_hash, lookup)? {
            Ok(outcome) => Ok(outcome),
            Err(outcome) => Ok(*outcome),
        }
    }

    fn run(
        &self,
        bundle: &[u8],
        hash_form: HashForm,
        content_hash: &Hash,
        lookup: &mut dyn Lookup,
    ) -> Result<Step<Outcome>, Unavailable> {
        // Steps 2 and 3: decode, then check the content.
        let bundle = match Bundle::decode(bundle) {
            Ok(bundle) => bundle,
            Err(malformed) => return Ok(Err(malformed.into())),
        };
        if bundle.leaf.body.hash_form != hash_form {
            return Ok(invalid(Invalid::WrongHashForm));
        }
        if &bundle.leaf.body.content_hash != content_hash {
            return Ok(invalid(Invalid::ContentMismatch));
        }

        // Step 4: complete the chain.
        let Bundle { leaf, certificates } = bundle;
        let chain = match self.complete(&leaf, certificates, lookup) {
            Ok(chain) => chain,
            Err(outcome) => return Ok(Err(outcome)),
        };

        // Step 5: check the links.
        let rooted_by = match self.check_links(&leaf, &chain)? {
            Ok(rooted_by) => rooted_by,
            Err(outcome) => return Ok(Err(outcome)),
        };

        // Step 6: check the warrants.
        if let Err(reason) = self.check_warrants(&leaf, &chain) {
            return Ok(invalid(reason));
        }

        // Step 7: apply revocations and distrust.
        let hashes: Vec<Hash> = chain.iter().map(|c| c.hash(self.crypto)).collect();
        let leaf_hash = leaf.hash(self.crypto);
        if self.revoked(&chain, &hashes, &leaf_hash, rooted_by.as_ref())? {
            return Ok(stop(Outcome::Refused(Refusal::Revoked)));
        }
        if self.distrusted(&hashes, &leaf_hash) {
            return Ok(stop(Outcome::Refused(Refusal::Distrusted)));
        }

        // Step 8: place the top-level.
        let top_level = hashes[hashes.len() - 1];
        let enabled = self.store.is_enabled(&top_level);
        let verified = Verified {
            name: leaf.body.name,
            warrants: leaf.body.warrants,
            top_level,
            root: rooted_by.filter(|_| enabled),
        };
        Ok(Ok(match (enabled, verified.root.is_some()) {
            (false, _) => Outcome::Consistent(verified),
            (true, true) => Outcome::Rooted(verified),
            (true, false) => Outcome::Unrooted(verified),
        }))
    }

    /// The whole chain from the leaf's issuer to a top-level: what the
    /// bundle carries, then each certificate it names and does not carry.
    fn complete(
        &self,
        leaf: &Leaf,
        carried: Vec<Certificate>,
        lookup: &mut dyn Lookup,
    ) -> Step<Vec<Certificate>> {
        let mut chain: Vec<Certificate> = Vec::new();
        let mut wanted = leaf.body.issuer;
        for certificate in carried {
            if chain
                .last()
                .is_some_and(|last| last.body.role == Role::TopLevel)
            {
                return invalid(Invalid::MisplacedTopLevel);
            }
            if certificate.hash(self.crypto) != wanted {
                return invalid(Invalid::OutOfOrder);
            }
            wanted = certificate.body.issuer;
            chain.push(certificate);
        }
        while chain
            .last()
            .is_none_or(|last| last.body.role != Role::TopLevel)
        {
            // A chain within the limit holds at most that many
            // intermediaries and nothing else yet.
            if chain.len() > MAX_INTERMEDIARIES {
                return invalid(Invalid::TooDeep);
            }
            let found = match self.store.top_level(&wanted) {
                Some(bytes) => bytes.to_vec(),
                None => lookup
                    .intermediary(&wanted)
                    .filter(|bytes| bytes.len() <= MAX_FOUND_CERTIFICATE_LEN)
                    .ok_or_else(|| Box::new(Outcome::Incomplete { missing: wanted }))?,
            };
            if self.crypto.sha512(&[&found]) != wanted {
                return invalid(Invalid::FoundHashMismatch);
            }
            let certificate = Certificate::decode(&found)?;
            wanted = certificate.body.issuer;
            chain.push(certificate);
        }
        if chain.len() - 1 > MAX_INTERMEDIARIES {
            return invalid(Invalid::TooDeep);
        }
        Ok(chain)
    }

    /// Verifies every signature, and returns the key hash of the root that
    /// signed the top-level, if one of this verifier's did.
    fn check_links(
        &self,
        leaf: &Leaf,
        chain: &[Certificate],
    ) -> Result<Step<Option<Hash>>, Unavailable> {
        let bad_signature = || Ok(invalid(Invalid::BadSignature));
        if !self.signed_by(&chain[0].body.key, leaf.signed_bytes(), leaf.signature())? {
            return bad_signature();
        }
        for pair in chain.windows(2) {
            let (child, issuer) = (&pair[0], &pair[1]);
            if child.body.role != Role::Intermediary {
                return Ok(invalid(Invalid::MisplacedTopLevel));
            }
            if !self.signed_by(&issuer.body.key, child.signed_bytes(), child.signature())? {
                return bad_signature();
            }
        }
        let top_level = &chain[chain.len() - 1];
        let issuer = top_level.body.issuer;
        if let Some(root) = self
            .roots
            .iter()
            .find(|root| root.hash(self.crypto) == issuer)
        {
            if !self.signed_by(root, top_level.signed_bytes(), top_level.signature())? {
                return bad_signature();
            }
            return Ok(Ok(Some(issuer)));
        }
        let own_key = &top_level.body.key;
        if own_key.hash(self.crypto) == issuer
            && !self.signed_by(own_key, top_level.signed_bytes(), top_level.signature())?
        {
            return bad_signature();
        }
        // Otherwise a key this verifier does not hold signed it, and there
        // is nothing to check the signature with.
        Ok(Ok(None))
    }

    /// Whether `signature` is `key`'s signature of `message`. A signature
    /// of any length but the key type's is not.
    fn signed_by(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool, Unavailable> {
        if signature.len() != key.key_type.signature_len() {
            return Ok(false);
        }
        self.crypto.verify(key, message, signature)
    }

    fn check_warrants(&self, leaf: &Leaf, chain: &[Certificate]) -> Result<(), Invalid> {
        for certificate in chain {
            self.check_known(&certificate.body.warrants)?;
        }
        self.check_known(&leaf.body.warrants)?;
        for pair in chain.windows(2) {
            let (child, issuer) = (&pair[0], &pair[1]);
            if issuer
                .warrant(DELEGATE)
                .and_then(Warrant::limit_value)
                .is_none_or(|n| n == 0)
            {
                return Err(Invalid::NoDelegate);
            }
            check_narrowing(&child.body.warrants, &issuer.body.warrants)?;
        }
        let issuer = &chain[0];
        for forbidden in [DELEGATE, NAME, REVOKE] {
            if warrant::find(&leaf.body.warrants, forbidden).is_some() {
                return Err(Invalid::ForbiddenInLeaf(forbidden.into()));
            }
        }
        check_narrowing(&leaf.body.warrants, &issuer.body.warrants)?;
        let held = issuer.warrant(NAME).is_some_and(|names| {
            names.elements().any(|parent| {
                core::str::from_utf8(parent)
                    .is_ok_and(|parent| name_is_within(&leaf.body.name, parent))
            })
        });
        if held {
            Ok(())
        } else {
            Err(Invalid::NameNotHeld)
        }
    }

    /// Checks that the warrants this chapter defines have the form it gives
    /// them, and that no unrecognized warrant is marked Must Understand.
    fn check_known(&self, warrants: &[Warrant]) -> Result<(), Invalid> {
        for warrant in warrants {
            let defined = match warrant.name() {
                DELEGATE => Some(DELEGATE_FLAGS),
                NAME => Some(NAME_FLAGS),
                REVOKE => Some(REVOKE_FLAGS),
                _ => None,
            };
            match defined {
                Some(flags) if warrant.flags() != flags => {
                    return Err(Invalid::WarrantMisdefined(warrant.name().into()));
                }
                Some(_) if warrant.name() == REVOKE && !warrant.value().is_empty() => {
                    return Err(Invalid::WarrantMisdefined(warrant.name().into()));
                }
                Some(_) => {}
                None if warrant.is_must_understand()
                    && !self.recognized.contains(&warrant.name()) =>
                {
                    return Err(Invalid::NotUnderstood(warrant.name().into()));
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Whether a revocation in the store applies to the chain (§7.12).
    fn revoked(
        &self,
        chain: &[Certificate],
        hashes: &[Hash],
        leaf_hash: &Hash,
        rooted_by: Option<&Hash>,
    ) -> Result<bool, Unavailable> {
        for revocation in &self.store.revocations {
            let body = &revocation.body;
            // Where the target stands: the leaf is beneath every
            // certificate, and certificate `i` is beneath those after it.
            let first_above = match body.target_type {
                TargetType::Leaf if &body.target == leaf_hash => 0,
                TargetType::Certificate => match hashes.iter().position(|h| h == &body.target) {
                    Some(index) => index + 1,
                    None => continue,
                },
                TargetType::Leaf => continue,
            };
            let is_self = body.target_type == TargetType::Certificate && body.signer == body.target;
            let signer = if is_self {
                Some(&chain[first_above - 1])
            } else {
                (first_above..chain.len())
                    .find(|i| hashes[*i] == body.signer)
                    .map(|i| &chain[i])
            };
            let key = match signer {
                Some(certificate) if certificate.warrant(REVOKE).is_some() => {
                    Some(&certificate.body.key)
                }
                Some(_) => None,
                // A root revokes only the top-level it signed.
                None if rooted_by == Some(&body.signer) && first_above == chain.len() => self
                    .roots
                    .iter()
                    .find(|root| root.hash(self.crypto) == body.signer),
                None => None,
            };
            if let Some(key) = key
                && self.signed_by(key, revocation.signed_bytes(), revocation.signature())?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn distrusted(&self, hashes: &[Hash], leaf_hash: &Hash) -> bool {
        self.store
            .distrust
            .iter()
            .any(|entry| match entry.target_type {
                TargetType::Certificate => hashes.contains(&entry.target),
                TargetType::Leaf => &entry.target == leaf_hash,
            })
    }
}

/// Checks every warrant of `child` against the warrants of the certificate
/// that issues it (§7.5, Narrowing). An authority calls this before it
/// signs, so that it never issues what a verifier would refuse.
pub fn check_narrowing(child: &[Warrant], parent: &[Warrant]) -> Result<(), Invalid> {
    warrant::narrow_all(child, parent).map_err(|(name, error)| {
        let name = String::from(name);
        match error {
            NarrowError::Added => Invalid::WarrantAdded(name),
            NarrowError::FlagsDiffer => Invalid::WarrantFlagsDiffer(name),
            NarrowError::Wider => Invalid::WarrantWidened(name),
            NarrowError::NotNarrower => Invalid::WarrantNotNarrowed(name),
        }
    })
}
