//! Which top-levels a trust store's directories enable (§7.10).

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use pso::core::{Certificate, Distrust, KeyType, RustCrypto, TargetType, Warrant};
use pso::keys::SecretKey;
use pso::{hex, issue, store};

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(KeyType::MlDsa65, [seed; 32])
}

fn name(certificate: &Certificate) -> String {
    hex::encode(&certificate.hash(&RustCrypto))
}

fn put(root: &Path, directory: &str, name: &str, bytes: &[u8]) {
    let directory = root.join(directory);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(name), bytes).unwrap();
}

fn rooted(root_key: &SecretKey) -> Certificate {
    let warrants = vec![Warrant::name_warrant(&["example.com"]).unwrap()];
    issue::top_level_under_root(root_key, "Rooted", &key(2).public(), warrants).unwrap()
}

fn self_signed() -> Certificate {
    let warrants = vec![Warrant::name_warrant(&["example.net"]).unwrap()];
    issue::top_level_self_signed(&key(3), "Self-Signed", warrants).unwrap()
}

#[test]
fn a_package_top_level_is_enabled_only_if_a_held_root_signed_it() {
    let system = tempfile::tempdir().unwrap();
    let root_key = key(1);
    let (rooted, own) = (rooted(&root_key), self_signed());
    put(
        system.path(),
        store::PACKAGE_TOP_LEVELS,
        &name(&rooted),
        rooted.bytes(),
    );
    put(
        system.path(),
        store::PACKAGE_TOP_LEVELS,
        &name(&own),
        own.bytes(),
    );

    let loaded = store::load(system.path(), &[root_key.public()]).unwrap();
    assert!(loaded.store.is_enabled(&rooted.hash(&RustCrypto)));
    assert!(!loaded.store.is_enabled(&own.hash(&RustCrypto)));
    assert_eq!(loaded.quarantined, vec![own.hash(&RustCrypto)]);

    // A verifier without that root enables neither.
    let loaded = store::load(system.path(), &[]).unwrap();
    assert_eq!(loaded.store.enabled().count(), 0);
    assert_eq!(loaded.quarantined.len(), 2);
}

#[test]
fn an_approval_link_enables_a_quarantined_top_level_until_it_is_withdrawn() {
    let system = tempfile::tempdir().unwrap();
    let own = self_signed();
    put(
        system.path(),
        store::PACKAGE_TOP_LEVELS,
        &name(&own),
        own.bytes(),
    );
    let local = system.path().join(store::LOCAL_TOP_LEVELS);
    fs::create_dir_all(&local).unwrap();
    // The link names the path on the system it is for, not under the
    // directory the test keeps that system in.
    let target = Path::new("/")
        .join(store::PACKAGE_TOP_LEVELS)
        .join(name(&own));
    symlink(&target, local.join(name(&own))).unwrap();

    let loaded = store::load(system.path(), &[]).unwrap();
    assert!(loaded.store.is_enabled(&own.hash(&RustCrypto)));
    assert!(loaded.quarantined.is_empty());

    fs::remove_file(
        system
            .path()
            .join(store::PACKAGE_TOP_LEVELS)
            .join(name(&own)),
    )
    .unwrap();
    let loaded = store::load(system.path(), &[]).unwrap();
    assert_eq!(loaded.store.enabled().count(), 0);
    assert!(
        loaded.ignored.is_empty(),
        "a withdrawn approval is not an error"
    );
}

#[test]
fn a_link_to_anything_else_enables_nothing() {
    let system = tempfile::tempdir().unwrap();
    let own = self_signed();
    let elsewhere = system.path().join("elsewhere");
    fs::write(&elsewhere, own.bytes()).unwrap();
    let local = system.path().join(store::LOCAL_TOP_LEVELS);
    fs::create_dir_all(&local).unwrap();
    symlink(&elsewhere, local.join(name(&own))).unwrap();

    let loaded = store::load(system.path(), &[]).unwrap();
    assert_eq!(loaded.store.enabled().count(), 0);
    assert_eq!(loaded.ignored.len(), 1);
}

#[test]
fn a_file_the_administrator_supplied_is_enabled() {
    let system = tempfile::tempdir().unwrap();
    let own = self_signed();
    put(
        system.path(),
        store::LOCAL_TOP_LEVELS,
        &name(&own),
        own.bytes(),
    );
    assert!(
        store::load(system.path(), &[])
            .unwrap()
            .store
            .is_enabled(&own.hash(&RustCrypto))
    );
}

#[test]
fn an_entry_not_named_by_its_hash_is_ignored() {
    let system = tempfile::tempdir().unwrap();
    let own = self_signed();
    put(
        system.path(),
        store::LOCAL_TOP_LEVELS,
        &"0".repeat(128),
        own.bytes(),
    );
    put(
        system.path(),
        store::LOCAL_TOP_LEVELS,
        "notes.txt",
        b"not a certificate",
    );
    let loaded = store::load(system.path(), &[]).unwrap();
    assert_eq!(loaded.store.enabled().count(), 0);
    assert_eq!(loaded.ignored.len(), 2);
}

#[test]
fn a_distrusted_top_level_is_not_enabled() {
    let system = tempfile::tempdir().unwrap();
    let root_key = key(1);
    let rooted = rooted(&root_key);
    put(
        system.path(),
        store::PACKAGE_TOP_LEVELS,
        &name(&rooted),
        rooted.bytes(),
    );
    let entry = Distrust {
        target_type: TargetType::Certificate,
        target: rooted.hash(&RustCrypto),
    };
    put(
        system.path(),
        store::LOCAL_DISTRUST,
        &name(&rooted),
        &entry.encode(),
    );

    let loaded = store::load(system.path(), &[root_key.public()]).unwrap();
    assert_eq!(loaded.store.enabled().count(), 0);
    assert_eq!(loaded.store.distrust, vec![entry]);
}
