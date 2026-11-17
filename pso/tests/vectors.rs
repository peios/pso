//! The test vectors in `vectors/pso.vectors`: chains with the result every
//! verifier must reach for them.
//!
//! The file is generated here from fixed seeds, so it is the same on every
//! run, and `vectors_are_current` fails if it has drifted from what this
//! file generates. Set `PSO_WRITE_VECTORS=1` to write it again.
//!
//! `vectors_verify` reads the file as another implementation would, with no
//! knowledge of how it was made, and checks every case against this one.
//! `vectors/README.md` describes the format.

use std::fmt::Write as _;
use std::path::PathBuf;

use pso::core::{
    Certificate, CertificateBody, Crypto, Distrust, Hash, HashForm, Key, KeyType, Leaf, LeafBody,
    Lookup, Outcome, Refusal, Revocation, RevocationBody, Role, RustCrypto, TargetType, TrustStore,
    Verifier, Warrant, encode_bundle,
};
use pso::keys::SecretKey;
use pso::{hex, issue};

const CONTENT: &[u8] = b"the bytes a leaf vouches for\n";

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/pso.vectors")
}

/// The key every run makes for `label`.
fn key(label: &str, key_type: KeyType) -> SecretKey {
    let digest = RustCrypto.sha512(&[b"pso test vector key ", label.as_bytes()]);
    SecretKey::from_seed(key_type, digest[..32].try_into().unwrap())
}

fn content_hash() -> Hash {
    RustCrypto.sha512(&[CONTENT])
}

#[derive(Clone, Default)]
struct Case {
    name: &'static str,
    about: &'static str,
    roots: Vec<Key>,
    top_levels: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
    revocations: Vec<Vec<u8>>,
    distrust: Vec<Vec<u8>>,
    recognized: Vec<&'static str>,
    hash_form: u8,
    content_hash: Vec<u8>,
    bundle: Vec<u8>,
    expect: &'static str,
    expect_name: Option<&'static str>,
    expect_refusal: Option<&'static str>,
}

/// The authorities the cases share: a root, a top-level it signs, an
/// intermediary beneath that, and a signing certificate beneath that.
struct World {
    root: SecretKey,
    top_key: SecretKey,
    top: Certificate,
    mid_key: SecretKey,
    mid: Certificate,
    signer_key: SecretKey,
    signer: Certificate,
}

fn world() -> World {
    let root = key("root", KeyType::MlDsa87);
    let top_key = key("top", KeyType::MlDsa65);
    let top = issue::top_level_under_root(
        &root,
        "Vector Top-Level",
        &top_key.public(),
        vec![
            Warrant::delegate(8),
            Warrant::name_warrant(&["example.com", "example.org"]).unwrap(),
            Warrant::revoke(),
            Warrant::set("Repository", &[], true).unwrap(),
            Warrant::set("Class", &["a", "b", "c"], true).unwrap(),
            Warrant::limit("Budget", 10, true).unwrap(),
        ],
    )
    .unwrap();
    let mid_key = key("mid", KeyType::MlDsa65);
    let mid = issue::intermediary(
        &top,
        &top_key,
        "Vector Intermediary",
        &mid_key.public(),
        vec![
            Warrant::delegate(4),
            Warrant::name_warrant(&["example.com"]).unwrap(),
            Warrant::revoke(),
            Warrant::set("Repository", &[], true).unwrap(),
            Warrant::set("Class", &["a", "b"], true).unwrap(),
            Warrant::limit("Budget", 5, true).unwrap(),
        ],
    )
    .unwrap();
    let signer_key = key("signer", KeyType::MlDsa65);
    let signer = issue::intermediary(
        &mid,
        &mid_key,
        "Vector Signing 1",
        &signer_key.public(),
        vec![
            Warrant::name_warrant(&["pkgs.example.com"]).unwrap(),
            Warrant::revoke(),
            Warrant::set("Repository", &[], true).unwrap(),
            Warrant::set("Class", &["a"], true).unwrap(),
        ],
    )
    .unwrap();
    World {
        root,
        top_key,
        top,
        mid_key,
        mid,
        signer_key,
        signer,
    }
}

impl World {
    fn leaf(&self) -> Leaf {
        issue::leaf(
            &self.signer,
            &self.signer_key,
            HashForm::WholeFile,
            content_hash(),
            "pkgs.example.com",
            vec![Warrant::set("Repository", &[], true).unwrap()],
        )
        .unwrap()
    }

    /// The usual case: the whole chain carried, the top-level enabled.
    fn base(&self, name: &'static str, about: &'static str) -> Case {
        Case {
            name,
            about,
            roots: vec![self.root.public()],
            top_levels: vec![self.top.bytes().to_vec()],
            hash_form: 0x01,
            content_hash: content_hash().to_vec(),
            bundle: bundle(&self.leaf(), &[&self.signer, &self.mid, &self.top]),
            expect: "rooted",
            expect_name: Some("pkgs.example.com"),
            ..Case::default()
        }
    }
}

fn bundle(leaf: &Leaf, certificates: &[&Certificate]) -> Vec<u8> {
    let certificates: Vec<&[u8]> = certificates.iter().map(|c| c.bytes()).collect();
    encode_bundle(leaf.bytes(), &certificates).unwrap()
}

/// A bundle of raw objects, for cases whose objects no encoder would write.
fn raw_bundle(leaf: &[u8], certificates: &[&[u8]]) -> Vec<u8> {
    let mut out = b"PSO\x03\x01\x00".to_vec();
    out.push(certificates.len() as u8);
    for object in std::iter::once(&leaf).chain(certificates) {
        out.extend_from_slice(&(object.len() as u16).to_le_bytes());
        out.extend_from_slice(object);
    }
    out
}

/// A certificate signed over exactly `body`, with nothing checked: what a
/// careless or hostile authority could issue.
fn unchecked_certificate(body: &CertificateBody, issuer_key: &SecretKey) -> Certificate {
    let signature = issuer_key.sign(&body.to_be_signed().unwrap()).unwrap();
    Certificate::from_signed(body, &signature).unwrap()
}

fn unchecked_leaf(body: &LeafBody, issuer_key: &SecretKey) -> Leaf {
    let signature = issuer_key.sign(&body.to_be_signed().unwrap()).unwrap();
    Leaf::from_signed(body, &signature).unwrap()
}

/// A signing certificate beneath the world's intermediary holding
/// `warrants`, and a leaf beneath it requesting `leaf_warrants`.
fn with_signer(
    world: &World,
    warrants: Vec<Warrant>,
    leaf_name: &str,
    leaf_warrants: Vec<Warrant>,
) -> Vec<u8> {
    let key = key("other signer", KeyType::MlDsa65);
    let signer = unchecked_certificate(
        &CertificateBody {
            role: Role::Intermediary,
            issuer: world.mid.hash(&RustCrypto),
            name: "Vector Signing 2".into(),
            key: key.public(),
            warrants,
        },
        &world.mid_key,
    );
    let leaf = unchecked_leaf(
        &LeafBody {
            hash_form: HashForm::WholeFile,
            content_hash: content_hash(),
            issuer: signer.hash(&RustCrypto),
            name: leaf_name.into(),
            warrants: leaf_warrants,
        },
        &key,
    );
    bundle(&leaf, &[&signer, &world.mid, &world.top])
}

fn names(names: &[&str]) -> Warrant {
    Warrant::name_warrant(names).unwrap()
}

// The cases are interleaved with the objects they are built from, so they
// are pushed one at a time.
#[allow(clippy::vec_init_then_push)]
fn cases() -> Vec<Case> {
    let w = world();
    let leaf = w.leaf();
    let repository = || Warrant::set("Repository", &[], true).unwrap();
    let mut cases = Vec::new();

    // Sound chains.
    cases.push(w.base(
        "rooted",
        "the whole chain carried, the top-level enabled and root-signed",
    ));
    cases.push(Case {
        bundle: bundle(&leaf, &[&w.signer, &w.mid]),
        ..w.base(
            "rooted-top-level-from-store",
            "the bundle stops below the top-level, which the store holds",
        )
    });
    cases.push(Case {
        bundle: bundle(&leaf, &[]),
        intermediates: vec![w.signer.bytes().to_vec(), w.mid.bytes().to_vec()],
        ..w.base(
            "rooted-intermediaries-found",
            "the bundle carries only the leaf, and both intermediaries are found by hash",
        )
    });
    cases.push(Case {
        top_levels: vec![],
        expect: "consistent",
        ..w.base(
            "consistent",
            "sound, and the top-level it carries is not enabled",
        )
    });
    cases.push(Case {
        roots: vec![],
        expect: "unrooted",
        ..w.base(
            "unrooted-unknown-root",
            "enabled, and signed by a root this verifier does not hold",
        )
    });
    let own_key = key("self-signed", KeyType::MlDsa65);
    let own = issue::top_level_self_signed(
        &own_key,
        "Vector Self-Signed",
        vec![names(&["example.net"]), repository()],
    )
    .unwrap();
    let own_leaf = issue::leaf(
        &own,
        &own_key,
        HashForm::WholeFile,
        content_hash(),
        "example.net",
        vec![repository()],
    )
    .unwrap();
    let self_signed = Case {
        top_levels: vec![own.bytes().to_vec()],
        bundle: bundle(&own_leaf, &[&own]),
        expect: "unrooted",
        expect_name: Some("example.net"),
        ..w.base(
            "unrooted-self-signed",
            "a self-signed top-level that is enabled signs the leaf itself",
        )
    };
    cases.push(self_signed.clone());
    cases.push(Case {
        top_levels: vec![],
        expect: "consistent",
        ..Case {
            name: "consistent-self-signed",
            about: "the same chain with the top-level not enabled",
            ..self_signed
        }
    });
    cases.push(Case {
        bundle: with_signer(
            &w,
            vec![
                names(&["pkgs.example.com"]),
                Warrant::set("com.example.Unknown", &["x"], true).unwrap(),
            ],
            "pkgs.example.com",
            vec![],
        ),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-unknown-warrant-added",
            "an unrecognized warrant still has to be held by the issuer",
        )
    });

    let elf_leaf = issue::leaf(
        &w.signer,
        &w.signer_key,
        HashForm::Elf,
        content_hash(),
        "pkgs.example.com",
        vec![],
    )
    .unwrap();
    cases.push(Case {
        hash_form: 0x02,
        bundle: bundle(&elf_leaf, &[&w.signer, &w.mid, &w.top]),
        ..w.base(
            "rooted-elf-form",
            "a leaf in the ELF hash form, verified where that form is called for",
        )
    });
    let small_root = key("small root", KeyType::MlDsa65);
    let small_top_key = key("small top", KeyType::MlDsa87);
    let small_top = issue::top_level_under_root(
        &small_root,
        "Vector Small Root",
        &small_top_key.public(),
        vec![names(&["example.com"])],
    )
    .unwrap();
    let small_leaf = issue::leaf(
        &small_top,
        &small_top_key,
        HashForm::WholeFile,
        content_hash(),
        "example.com",
        vec![],
    )
    .unwrap();
    cases.push(Case {
        roots: vec![w.root.public(), small_root.public()],
        top_levels: vec![small_top.bytes().to_vec()],
        bundle: bundle(&small_leaf, &[]),
        expect_name: Some("example.com"),
        ..w.base(
            "rooted-second-root",
            "a second root, ML-DSA-65, signs an ML-DSA-87 top-level that signs the leaf",
        )
    });

    // The content and the bundle.
    cases.push(Case {
        content_hash: RustCrypto.sha512(&[b"other bytes"]).to_vec(),
        expect: "invalid",
        expect_name: None,
        ..w.base("invalid-content", "the content hash is not the file's")
    });
    cases.push(Case {
        hash_form: 0x02,
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-hash-form",
            "the place calls for the ELF form and the leaf has the whole-file form",
        )
    });
    let mut trailing = w.base(
        "invalid-trailing-byte",
        "a byte after the bundle's last field",
    );
    trailing.bundle.push(0);
    cases.push(Case {
        expect: "invalid",
        expect_name: None,
        ..trailing
    });
    let mut version = w.base(
        "invalid-version",
        "a format version this specification does not define",
    );
    version.bundle[4] = 0x02;
    cases.push(Case {
        expect: "invalid",
        expect_name: None,
        ..version
    });
    let mut reserved = w.base("invalid-reserved-byte", "the header's reserved byte is set");
    reserved.bundle[5] = 0x01;
    cases.push(Case {
        expect: "invalid",
        expect_name: None,
        ..reserved
    });
    cases.push(Case {
        bundle: bundle(&leaf, &[&w.mid, &w.signer, &w.top]),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-order",
            "the carried certificates are not each the issuer of the one before",
        )
    });
    cases.push(Case {
        bundle: bundle(&leaf, &[&w.signer]),
        expect: "incomplete",
        expect_name: None,
        ..w.base(
            "incomplete",
            "the bundle names an intermediary that is nowhere to be found",
        )
    });

    // Signatures.
    let mut forged = leaf.bytes().to_vec();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    cases.push(Case {
        bundle: raw_bundle(&forged, &[w.signer.bytes(), w.mid.bytes(), w.top.bytes()]),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-leaf-signature",
            "one bit of the leaf's signature is flipped",
        )
    });
    let stranger = key("stranger", KeyType::MlDsa65);
    let wrong_key_leaf = unchecked_leaf(&leaf.body, &stranger);
    cases.push(Case {
        bundle: bundle(&wrong_key_leaf, &[&w.signer, &w.mid, &w.top]),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-leaf-signer",
            "the leaf is signed by a key that is not its issuer's",
        )
    });
    let impostor = unchecked_certificate(&w.top.body, &stranger);
    cases.push(Case {
        top_levels: vec![impostor.bytes().to_vec()],
        bundle: bundle(&leaf, &[&w.signer, &w.mid]),
        expect: "incomplete",
        expect_name: None,
        ..w.base(
            "incomplete-impostor-top-level",
            "a top-level the root did not sign has another hash, so the chain cannot reach it",
        )
    });
    let bad_root = unchecked_certificate(&w.top.body, &stranger);
    let bad_mid = unchecked_certificate(
        &CertificateBody {
            issuer: bad_root.hash(&RustCrypto),
            ..w.mid.body.clone()
        },
        &w.top_key,
    );
    let bad_signer = unchecked_certificate(
        &CertificateBody {
            issuer: bad_mid.hash(&RustCrypto),
            ..w.signer.body.clone()
        },
        &w.mid_key,
    );
    let bad_leaf = unchecked_leaf(
        &LeafBody {
            issuer: bad_signer.hash(&RustCrypto),
            ..leaf.body.clone()
        },
        &w.signer_key,
    );
    cases.push(Case {
        top_levels: vec![bad_root.bytes().to_vec()],
        bundle: bundle(&bad_leaf, &[&bad_signer, &bad_mid, &bad_root]),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-root-signature",
            "the top-level names a root this verifier holds, and that root did not sign it",
        )
    });

    // Warrants.
    let invalid = |name, about, bundle| Case {
        bundle,
        expect: "invalid",
        expect_name: None,
        ..w.base(name, about)
    };
    cases.push(invalid(
        "invalid-warrant-added",
        "a certificate holds a warrant its issuer does not",
        with_signer(
            &w,
            vec![
                names(&["pkgs.example.com"]),
                Warrant::set("Extra", &[], true).unwrap(),
            ],
            "pkgs.example.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-set-widened",
        "a Set holds an element its issuer's does not",
        with_signer(
            &w,
            vec![
                names(&["pkgs.example.com"]),
                Warrant::set("Class", &["a", "c"], true).unwrap(),
            ],
            "pkgs.example.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-limit-widened",
        "a Limit is greater than its issuer's",
        with_signer(
            &w,
            vec![
                names(&["pkgs.example.com"]),
                Warrant::limit("Budget", 6, true).unwrap(),
            ],
            "pkgs.example.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-namespace-widened",
        "a name outside its issuer's namespace",
        with_signer(&w, vec![names(&["example.org"])], "example.org", vec![]),
    ));
    cases.push(invalid(
        "invalid-namespace-suffix",
        "evilexample.com ends with example.com and is not within it",
        with_signer(
            &w,
            vec![names(&["evilexample.com"])],
            "evilexample.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-flags-differ",
        "a warrant whose Allow Equal flag differs from its issuer's",
        with_signer(
            &w,
            vec![
                names(&["pkgs.example.com"]),
                Warrant::limit("Budget", 3, false).unwrap(),
            ],
            "pkgs.example.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-delegate-not-narrowed",
        "Delegate equal to its issuer's, where it must be smaller",
        with_signer(
            &w,
            vec![names(&["pkgs.example.com"]), Warrant::delegate(4)],
            "pkgs.example.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-leaf-name",
        "a leaf issued under a name its issuer's Name does not cover",
        with_signer(
            &w,
            vec![names(&["pkgs.example.com"])],
            "other.example.com",
            vec![],
        ),
    ));
    cases.push(invalid(
        "invalid-leaf-without-name-warrant",
        "a leaf issued by a certificate that holds no Name",
        with_signer(&w, vec![repository()], "pkgs.example.com", vec![]),
    ));
    cases.push(invalid(
        "invalid-leaf-holds-delegate",
        "a leaf holding Delegate",
        with_signer(
            &w,
            vec![names(&["pkgs.example.com"]), Warrant::delegate(2)],
            "pkgs.example.com",
            vec![Warrant::delegate(1)],
        ),
    ));
    cases.push(invalid(
        "invalid-leaf-warrant-added",
        "a leaf requesting a warrant its issuer does not hold",
        with_signer(
            &w,
            vec![names(&["pkgs.example.com"])],
            "pkgs.example.com",
            vec![repository()],
        ),
    ));

    // A certificate issued by one with no Delegate.
    let below_key = key("below", KeyType::MlDsa65);
    let below = unchecked_certificate(
        &CertificateBody {
            role: Role::Intermediary,
            issuer: w.signer.hash(&RustCrypto),
            name: "Vector Below".into(),
            key: below_key.public(),
            warrants: vec![names(&["pkgs.example.com"])],
        },
        &w.signer_key,
    );
    let below_leaf = unchecked_leaf(
        &LeafBody {
            issuer: below.hash(&RustCrypto),
            warrants: vec![],
            ..leaf.body.clone()
        },
        &below_key,
    );
    cases.push(invalid(
        "invalid-no-delegate",
        "a certificate issued by one that holds no Delegate",
        bundle(&below_leaf, &[&below, &w.signer, &w.mid, &w.top]),
    ));

    // Must Understand.
    let must_top_key = key("must top", KeyType::MlDsa65);
    let must = Warrant::set("com.example.Must", &[], true)
        .unwrap()
        .must_understand();
    let must_top = issue::top_level_under_root(
        &w.root,
        "Vector Must",
        &must_top_key.public(),
        vec![names(&["example.com"]), must.clone()],
    )
    .unwrap();
    let must_leaf = issue::leaf(
        &must_top,
        &must_top_key,
        HashForm::WholeFile,
        content_hash(),
        "example.com",
        vec![must],
    )
    .unwrap();
    let must_case = Case {
        top_levels: vec![must_top.bytes().to_vec()],
        bundle: bundle(&must_leaf, &[&must_top]),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-must-understand",
            "a warrant marked Must Understand that the verifier does not recognize",
        )
    };
    cases.push(must_case.clone());
    cases.push(Case {
        name: "rooted-must-understand-recognized",
        about: "the same chain, verified by a verifier that recognizes the warrant",
        recognized: vec!["com.example.Must"],
        expect: "rooted",
        expect_name: Some("example.com"),
        ..must_case
    });

    // Depth: seventeen intermediaries between the leaf and the top-level.
    let mut deep: Vec<(SecretKey, Certificate)> = Vec::new();
    for depth in 0..17u64 {
        let (issuer, issuer_key) = match deep.last() {
            Some((key, certificate)) => (
                certificate.clone(),
                SecretKey::from_seed(key.key_type(), seed_of(depth - 1)),
            ),
            None => (
                w.top.clone(),
                SecretKey::from_seed(KeyType::MlDsa65, seed_named("top")),
            ),
        };
        let next = SecretKey::from_seed(KeyType::MlDsa65, seed_of(depth));
        let certificate = unchecked_certificate(
            &CertificateBody {
                role: Role::Intermediary,
                issuer: issuer.hash(&RustCrypto),
                name: format!("Vector Deep {depth}"),
                key: next.public(),
                warrants: vec![names(&["example.com"])],
            },
            &issuer_key,
        );
        deep.push((next, certificate));
    }
    let (deep_key, deepest) = deep.last().unwrap();
    let deep_leaf = unchecked_leaf(
        &LeafBody {
            issuer: deepest.hash(&RustCrypto),
            name: "example.com".into(),
            warrants: vec![],
            ..leaf.body.clone()
        },
        deep_key,
    );
    cases.push(Case {
        intermediates: deep
            .iter()
            .map(|(_, certificate)| certificate.bytes().to_vec())
            .collect(),
        bundle: bundle(&deep_leaf, &[]),
        expect: "invalid",
        expect_name: None,
        ..w.base(
            "invalid-too-deep",
            "seventeen intermediaries, one more than a chain can hold",
        )
    });

    // Revocation and distrust.
    let revoke = |signer: &Certificate, signer_key: &SecretKey, target_type, target| {
        issue::revocation_by_certificate(signer, signer_key, target_type, target)
            .unwrap()
            .bytes()
            .to_vec()
    };
    let refused = |name, about, refusal| Case {
        expect: "refused",
        expect_name: None,
        expect_refusal: Some(refusal),
        ..w.base(name, about)
    };
    cases.push(Case {
        revocations: vec![revoke(
            &w.signer,
            &w.signer_key,
            TargetType::Certificate,
            w.signer.hash(&RustCrypto),
        )],
        ..refused(
            "refused-revoked-itself",
            "the signing certificate revoked itself",
            "revoked",
        )
    });
    cases.push(Case {
        revocations: vec![revoke(
            &w.mid,
            &w.mid_key,
            TargetType::Certificate,
            w.signer.hash(&RustCrypto),
        )],
        ..refused(
            "refused-revoked-by-ancestor",
            "the intermediary above the signing certificate revoked it",
            "revoked",
        )
    });
    cases.push(Case {
        revocations: vec![revoke(
            &w.signer,
            &w.signer_key,
            TargetType::Leaf,
            leaf.hash(&RustCrypto),
        )],
        ..refused(
            "refused-leaf-revoked",
            "the leaf's issuer revoked the leaf",
            "revoked",
        )
    });
    cases.push(Case {
        revocations: vec![
            issue::revocation_by_root(&w.root, &w.top)
                .unwrap()
                .bytes()
                .to_vec(),
        ],
        ..refused(
            "refused-revoked-by-root",
            "the root revoked the top-level it signed",
            "revoked",
        )
    });
    cases.push(Case {
        revocations: vec![revoke(
            &w.signer,
            &w.signer_key,
            TargetType::Certificate,
            w.mid.hash(&RustCrypto),
        )],
        ..w.base(
            "rooted-revocation-from-below",
            "a certificate cannot revoke the one above it, so the revocation is ignored",
        )
    });
    let outsider_key = key("outsider", KeyType::MlDsa65);
    let outsider =
        issue::top_level_self_signed(&outsider_key, "Vector Outsider", vec![Warrant::revoke()])
            .unwrap();
    cases.push(Case {
        revocations: vec![revoke(
            &outsider,
            &outsider_key,
            TargetType::Certificate,
            w.signer.hash(&RustCrypto),
        )],
        ..w.base(
            "rooted-revocation-by-outsider",
            "a certificate outside the chain cannot revoke within it",
        )
    });
    let forged_revocation = {
        let body = RevocationBody {
            target_type: TargetType::Certificate,
            target: w.signer.hash(&RustCrypto),
            signer: w.mid.hash(&RustCrypto),
        };
        let signature = stranger.sign(&body.to_be_signed()).unwrap();
        Revocation::from_signed(&body, &signature)
            .unwrap()
            .bytes()
            .to_vec()
    };
    cases.push(Case {
        revocations: vec![forged_revocation],
        ..w.base(
            "rooted-revocation-forged",
            "a revocation naming an ancestor as its signer and not signed by it",
        )
    });
    cases.push(Case {
        distrust: vec![
            Distrust {
                target_type: TargetType::Certificate,
                target: w.mid.hash(&RustCrypto),
            }
            .encode(),
        ],
        ..refused(
            "refused-distrusted-certificate",
            "the administrator distrusts the intermediary",
            "distrusted",
        )
    });
    cases.push(Case {
        distrust: vec![
            Distrust {
                target_type: TargetType::Leaf,
                target: leaf.hash(&RustCrypto),
            }
            .encode(),
        ],
        ..refused(
            "refused-distrusted-leaf",
            "the administrator distrusts the leaf",
            "distrusted",
        )
    });
    cases
}

fn seed_named(label: &str) -> [u8; 32] {
    RustCrypto.sha512(&[b"pso test vector key ", label.as_bytes()])[..32]
        .try_into()
        .unwrap()
}

fn seed_of(depth: u64) -> [u8; 32] {
    seed_named(&format!("deep {depth}"))
}

fn render(cases: &[Case]) -> String {
    let mut out =
        String::from("# PSO test vectors. Generated by pso/tests/vectors.rs; do not edit.\n");
    for case in cases {
        writeln!(out, "\ncase {}", case.name).unwrap();
        writeln!(out, "about {}", case.about).unwrap();
        for root in &case.roots {
            writeln!(
                out,
                "root {:02x}{}",
                root.key_type.byte(),
                hex::encode(&root.bytes)
            )
            .unwrap();
        }
        for (label, objects) in [
            ("toplevel", &case.top_levels),
            ("intermediate", &case.intermediates),
            ("revocation", &case.revocations),
            ("distrust", &case.distrust),
        ] {
            for object in objects {
                writeln!(out, "{label} {}", hex::encode(object)).unwrap();
            }
        }
        for name in &case.recognized {
            writeln!(out, "recognize {name}").unwrap();
        }
        writeln!(out, "hash-form {:02x}", case.hash_form).unwrap();
        writeln!(out, "content-hash {}", hex::encode(&case.content_hash)).unwrap();
        writeln!(out, "bundle {}", hex::encode(&case.bundle)).unwrap();
        writeln!(out, "expect {}", case.expect).unwrap();
        if let Some(name) = case.expect_name {
            writeln!(out, "expect-name {name}").unwrap();
        }
        if let Some(refusal) = case.expect_refusal {
            writeln!(out, "expect-refusal {refusal}").unwrap();
        }
        writeln!(out, "end").unwrap();
    }
    out
}

#[test]
fn vectors_are_current() {
    let rendered = render(&cases());
    if std::env::var_os("PSO_WRITE_VECTORS").is_some() {
        std::fs::write(vectors_path(), &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(vectors_path()).unwrap_or_default();
    assert!(
        committed == rendered,
        "vectors/pso.vectors is not what this test generates; run with PSO_WRITE_VECTORS=1"
    );
}

/// Finds intermediaries among the ones a case lists.
struct Listed(Vec<Vec<u8>>);

impl Lookup for Listed {
    fn intermediary(&mut self, hash: &Hash) -> Option<Vec<u8>> {
        self.0
            .iter()
            .find(|bytes| &RustCrypto.sha512(&[bytes]) == hash)
            .cloned()
    }
}

#[test]
fn vectors_verify() {
    let text = std::fs::read_to_string(vectors_path()).expect("vectors/pso.vectors");
    let mut checked = 0;
    let mut case: Option<(String, Vec<(String, String)>)> = None;
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        match word {
            "case" => case = Some((rest.into(), Vec::new())),
            "end" => {
                let (name, fields) = case.take().expect("end without case");
                check(&name, &fields);
                checked += 1;
            }
            _ => case
                .as_mut()
                .expect("field outside a case")
                .1
                .push((word.into(), rest.into())),
        }
    }
    assert!(checked >= 40, "only {checked} cases were read");
}

fn check(name: &str, fields: &[(String, String)]) {
    let all = |wanted: &str| -> Vec<&str> {
        fields
            .iter()
            .filter(|(word, _)| word == wanted)
            .map(|(_, rest)| rest.as_str())
            .collect()
    };
    let one = |wanted: &str| all(wanted).first().copied();
    let bytes = |wanted: &str| -> Vec<Vec<u8>> {
        all(wanted)
            .into_iter()
            .map(|text| hex::decode(text).unwrap())
            .collect()
    };

    let roots: Vec<Key> = bytes("root")
        .into_iter()
        .map(|root| Key::new(KeyType::from_byte(root[0]).unwrap(), root[1..].to_vec()).unwrap())
        .collect();
    let mut store = TrustStore::new();
    for top_level in bytes("toplevel") {
        store.enable(&RustCrypto, &top_level).unwrap();
    }
    store.revocations = bytes("revocation")
        .iter()
        .map(|b| Revocation::decode(b).unwrap())
        .collect();
    store.distrust = bytes("distrust")
        .iter()
        .map(|b| Distrust::decode(b).unwrap())
        .collect();
    let recognized = all("recognize");
    let verifier = Verifier {
        crypto: &RustCrypto,
        roots: &roots,
        store: &store,
        recognized: &recognized,
    };

    let hash_form =
        HashForm::from_byte(hex::decode(one("hash-form").unwrap()).unwrap()[0]).unwrap();
    let content_hash = hex::decode_hash(one("content-hash").unwrap()).unwrap();
    let bundle = hex::decode(one("bundle").unwrap()).unwrap();
    let outcome = verifier
        .verify(
            &bundle,
            hash_form,
            &content_hash,
            &mut Listed(bytes("intermediate")),
        )
        .unwrap();

    assert_eq!(
        outcome.name(),
        one("expect").unwrap(),
        "{name}: {outcome:?}"
    );
    assert_eq!(
        outcome.verified().map(|v| v.name.as_str()),
        one("expect-name"),
        "{name}"
    );
    let refusal = match outcome {
        Outcome::Refused(Refusal::Revoked) => Some("revoked"),
        Outcome::Refused(Refusal::Distrusted) => Some("distrusted"),
        _ => None,
    };
    assert_eq!(refusal, one("expect-refusal"), "{name}");
}
