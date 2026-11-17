//! The `pso` command, from making a root to verifying a signed file.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn pso(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pso"))
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("running pso")
}

fn ok(directory: &Path, arguments: &[&str]) -> String {
    let output = pso(directory, arguments);
    assert!(
        output.status.success(),
        "pso {arguments:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// A root, a top-level it signs, and a signing certificate beneath that,
/// with the top-level installed in the trust store of a system at `sys`.
fn authority(directory: &Path) {
    ok(directory, &["root", "--out", "root.key"]);
    ok(directory, &["key", "new", "--out", "top.key"]);
    ok(directory, &["key", "new", "--out", "signer.key"]);
    let top = ok(
        directory,
        &[
            "cert",
            "top-level",
            "--name",
            "Example Top",
            "--root-key",
            "root.key",
            "--key",
            "top.key.pub",
            "--warrant",
            "Delegate=1",
            "--warrant",
            "Name=example.com",
            "--warrant",
            "Revoke",
            "--warrant",
            "Repository",
            "--out",
            "top.cert",
        ],
    );
    ok(
        directory,
        &[
            "cert",
            "intermediary",
            "--name",
            "Example Signing",
            "--key",
            "signer.key.pub",
            "--issuer",
            "top.cert",
            "--issuer-key",
            "top.key",
            "--warrant",
            "Name=pkgs.example.com",
            "--warrant",
            "Revoke",
            "--warrant",
            "Repository",
            "--out",
            "signer.cert",
        ],
    );
    let store = directory.join("sys/usr/share/pso/toplevel");
    fs::create_dir_all(&store).unwrap();
    fs::copy(directory.join("top.cert"), store.join(top.trim())).unwrap();
}

const VERIFY: &[&str] = &[
    "verify",
    "repository",
    "--bundle",
    "repository.pso",
    "--root",
    "root.key.pub",
    "--store",
    "sys",
];

#[test]
fn a_signed_file_verifies_as_rooted_until_it_changes() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    authority(directory);
    fs::write(directory.join("repository"), "sequence 1\n").unwrap();
    ok(
        directory,
        &[
            "sign",
            "repository",
            "--issuer",
            "signer.cert",
            "--issuer-key",
            "signer.key",
            "--name",
            "pkgs.example.com",
            "--warrant",
            "Repository",
        ],
    );
    let verified = ok(directory, VERIFY);
    assert!(verified.starts_with("rooted\n"), "{verified}");
    assert!(
        verified.contains("name       pkgs.example.com"),
        "{verified}"
    );
    assert!(verified.contains("warrant    Repository"), "{verified}");

    fs::write(directory.join("repository"), "sequence 2\n").unwrap();
    let changed = pso(directory, VERIFY);
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stdout).starts_with("invalid\n"));
}

#[test]
fn a_revoked_signing_certificate_refuses_what_it_signed() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    authority(directory);
    fs::write(directory.join("repository"), "sequence 1\n").unwrap();
    ok(
        directory,
        &[
            "sign",
            "repository",
            "--issuer",
            "signer.cert",
            "--issuer-key",
            "signer.key",
            "--name",
            "pkgs.example.com",
        ],
    );
    let revocation = ok(
        directory,
        &[
            "revoke",
            "signer.cert",
            "--signer",
            "top.cert",
            "--signer-key",
            "top.key",
            "--out",
            "r",
        ],
    );
    let held = directory.join("sys/lcl/policy/pso/revocation");
    fs::create_dir_all(&held).unwrap();
    fs::copy(directory.join("r"), held.join(revocation.trim())).unwrap();

    let refused = pso(directory, VERIFY);
    assert!(!refused.status.success());
    assert_eq!(
        String::from_utf8_lossy(&refused.stdout),
        "refused\n  revoked\n"
    );
}

#[test]
fn an_authority_cannot_issue_what_a_verifier_would_refuse() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    authority(directory);
    fs::write(directory.join("repository"), "sequence 1\n").unwrap();
    let outside = pso(
        directory,
        &[
            "sign",
            "repository",
            "--issuer",
            "signer.cert",
            "--issuer-key",
            "signer.key",
            "--name",
            "pkgs.example.org",
        ],
    );
    assert!(!outside.status.success());
    assert!(String::from_utf8_lossy(&outside.stderr).contains("Name warrant does not cover"));

    // The signing certificate holds no Delegate, so it issues leaves only.
    ok(directory, &["key", "new", "--out", "below.key"]);
    let below = pso(
        directory,
        &[
            "cert",
            "intermediary",
            "--name",
            "Below",
            "--key",
            "below.key.pub",
            "--issuer",
            "signer.cert",
            "--issuer-key",
            "signer.key",
            "--out",
            "below.cert",
        ],
    );
    assert!(!below.status.success());
    assert!(String::from_utf8_lossy(&below.stderr).contains("no Delegate warrant"));
}

#[test]
fn a_secret_key_is_never_replaced_and_only_its_owner_reads_it() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    ok(directory, &["root", "--out", "root.key"]);
    let mode = fs::metadata(directory.join("root.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let before = fs::read(directory.join("root.key")).unwrap();
    assert!(
        !pso(directory, &["root", "--out", "root.key"])
            .status
            .success()
    );
    assert_eq!(fs::read(directory.join("root.key")).unwrap(), before);
}
