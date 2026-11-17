//! What an authority does: issue certificates and leaves, and revoke them.
//!
//! Each function checks what it is about to sign against the rules a
//! verifier applies, so that an authority never issues what would be
//! refused (§7.16).

use anyhow::{Result, anyhow, bail};

use pso_core::{
    Certificate, CertificateBody, DELEGATE, Hash, HashForm, Invalid, Key, Leaf, LeafBody, NAME,
    REVOKE, Revocation, RevocationBody, Role, RustCrypto, TargetType, Warrant, check_narrowing,
    name_is_within,
};

use crate::keys::SecretKey;

/// A top-level that `root` signs, binding `subject` to `name` and
/// `warrants`.
pub fn top_level_under_root(
    root: &SecretKey,
    name: &str,
    subject: &Key,
    warrants: Vec<Warrant>,
) -> Result<Certificate> {
    let body = CertificateBody {
        role: Role::TopLevel,
        issuer: root.public().hash(&RustCrypto),
        name: name.into(),
        key: subject.clone(),
        warrants,
    };
    sign_certificate(&body, root)
}

/// A top-level that signs itself with `subject`.
pub fn top_level_self_signed(
    subject: &SecretKey,
    name: &str,
    warrants: Vec<Warrant>,
) -> Result<Certificate> {
    let key = subject.public();
    let body = CertificateBody {
        role: Role::TopLevel,
        issuer: key.hash(&RustCrypto),
        name: name.into(),
        key,
        warrants,
    };
    sign_certificate(&body, subject)
}

/// An intermediary that `issuer` issues, binding `subject` to `name` and
/// `warrants`.
pub fn intermediary(
    issuer: &Certificate,
    issuer_key: &SecretKey,
    name: &str,
    subject: &Key,
    warrants: Vec<Warrant>,
) -> Result<Certificate> {
    holds_key(issuer, issuer_key)?;
    if issuer
        .warrant(DELEGATE)
        .and_then(Warrant::limit_value)
        .is_none_or(|depth| depth == 0)
    {
        bail!("the issuer holds no Delegate warrant, so it can issue leaves only");
    }
    check_narrowing(&warrants, &issuer.body.warrants).map_err(describe)?;
    let body = CertificateBody {
        role: Role::Intermediary,
        issuer: issuer.hash(&RustCrypto),
        name: name.into(),
        key: subject.clone(),
        warrants,
    };
    sign_certificate(&body, issuer_key)
}

/// A leaf that `issuer` issues under `name`, for a file whose content hash
/// in `hash_form` is `content_hash`.
pub fn leaf(
    issuer: &Certificate,
    issuer_key: &SecretKey,
    hash_form: HashForm,
    content_hash: Hash,
    name: &str,
    warrants: Vec<Warrant>,
) -> Result<Leaf> {
    holds_key(issuer, issuer_key)?;
    for forbidden in [DELEGATE, NAME, REVOKE] {
        if warrants.iter().any(|warrant| warrant.name() == forbidden) {
            bail!("a leaf cannot hold {forbidden}");
        }
    }
    check_narrowing(&warrants, &issuer.body.warrants).map_err(describe)?;
    let within = issuer.warrant(NAME).is_some_and(|names| {
        names
            .elements()
            .any(|parent| std::str::from_utf8(parent).is_ok_and(|p| name_is_within(name, p)))
    });
    if !within {
        bail!("the issuer's Name warrant does not cover {name}");
    }
    let body = LeafBody {
        hash_form,
        content_hash,
        issuer: issuer.hash(&RustCrypto),
        name: name.into(),
        warrants,
    };
    let to_be_signed = body
        .to_be_signed()
        .map_err(|e| anyhow!("the leaf is malformed: {e:?}"))?;
    let signature = issuer_key.sign(&to_be_signed)?;
    Leaf::from_signed(&body, &signature).map_err(|e| anyhow!("the leaf is malformed: {e:?}"))
}

/// A revocation of `target` that the certificate `signer` signs. The
/// signer is the target itself or stands above it, which only a chain can
/// show, so this checks only that the signer holds `Revoke`.
pub fn revocation_by_certificate(
    signer: &Certificate,
    signer_key: &SecretKey,
    target_type: TargetType,
    target: Hash,
) -> Result<Revocation> {
    holds_key(signer, signer_key)?;
    if signer.warrant(REVOKE).is_none() {
        bail!("the signer holds no Revoke warrant");
    }
    sign_revocation(
        &RevocationBody {
            target_type,
            target,
            signer: signer.hash(&RustCrypto),
        },
        signer_key,
    )
}

/// A revocation of the top-level `target` that `root`, which signed it,
/// signs.
pub fn revocation_by_root(root: &SecretKey, target: &Certificate) -> Result<Revocation> {
    let signer = root.public().hash(&RustCrypto);
    if target.body.role != Role::TopLevel || target.body.issuer != signer {
        bail!("a root revokes only a top-level it signed");
    }
    sign_revocation(
        &RevocationBody {
            target_type: TargetType::Certificate,
            target: target.hash(&RustCrypto),
            signer,
        },
        root,
    )
}

fn sign_certificate(body: &CertificateBody, key: &SecretKey) -> Result<Certificate> {
    let to_be_signed = body
        .to_be_signed()
        .map_err(|e| anyhow!("the certificate is malformed: {e:?}"))?;
    let signature = key.sign(&to_be_signed)?;
    Certificate::from_signed(body, &signature)
        .map_err(|e| anyhow!("the certificate is malformed: {e:?}"))
}

fn sign_revocation(body: &RevocationBody, key: &SecretKey) -> Result<Revocation> {
    let signature = key.sign(&body.to_be_signed())?;
    Revocation::from_signed(body, &signature)
        .map_err(|e| anyhow!("the revocation is malformed: {e:?}"))
}

/// Fails unless `key` is the secret key of `certificate`.
fn holds_key(certificate: &Certificate, key: &SecretKey) -> Result<()> {
    if certificate.body.key == key.public() {
        Ok(())
    } else {
        bail!("the key is not the certificate's")
    }
}

fn describe(invalid: Invalid) -> anyhow::Error {
    match invalid {
        Invalid::WarrantAdded(name) => anyhow!("the issuer does not hold {name}"),
        Invalid::WarrantFlagsDiffer(name) => {
            anyhow!("{name} has a type or flags that differ from the issuer's")
        }
        Invalid::WarrantWidened(name) => anyhow!("{name} is wider than the issuer's"),
        Invalid::WarrantNotNarrowed(name) => {
            anyhow!("{name} must be narrower than the issuer's, and is equal to it")
        }
        other => anyhow!("{other:?}"),
    }
}
