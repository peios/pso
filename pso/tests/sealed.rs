//! Keys sealed under a passphrase: the sealed format against peios-crypto's
//! own blobs, and the `pso` commands that make, open, seal and reseal them.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use pso::passphrase::{NewPassphrase, Passphrase};
use pso::{hex, seal};

const PASSPHRASE: &str = "correct horse battery staple";
const OTHER: &str = "a different passphrase entirely";

/// Each case of `vectors/peioseal.vectors`, as its fields.
fn vectors() -> Vec<Vec<(String, String)>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/peioseal.vectors");
    let text = fs::read_to_string(path).unwrap();
    let mut cases = Vec::new();
    let mut case = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        match word {
            "end" => cases.push(std::mem::take(&mut case)),
            _ => case.push((word.to_owned(), rest.to_owned())),
        }
    }
    cases
}

#[test]
fn blobs_sealed_by_peios_crypto_open_here() {
    let cases = vectors();
    assert!(cases.len() >= 2, "only {} cases", cases.len());
    for case in cases {
        let field = |name: &str| &case.iter().find(|(word, _)| word == name).unwrap().1;
        let name = field("case");
        let typed = Passphrase::new(field("typed"));
        assert_eq!(
            hex::encode(typed.bytes()),
            *field("passphrase"),
            "{name}: NFKC form"
        );
        let blob = hex::decode(field("blob")).unwrap();
        let plaintext = seal::open(&blob, typed.bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex::encode(&plaintext), *field("plaintext"), "{name}");
        assert!(seal::open(&blob, b"not the passphrase").is_err(), "{name}");
    }
}

#[test]
fn a_new_passphrase_needs_fifteen_characters_after_normalising() {
    assert!(NewPassphrase::new("fourteen chars").is_err());
    assert!(NewPassphrase::new("fifteen chars!!").is_ok());
    // Five letters with combining accents are five characters, not ten.
    assert!(NewPassphrase::new("a\u{301}e\u{301}i\u{301}o\u{301}u\u{301}xxxxxxxxx").is_err());
}

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

fn failure(directory: &Path, arguments: &[&str]) -> String {
    let output = pso(directory, arguments);
    assert!(!output.status.success(), "pso {arguments:?} succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A directory holding the two passphrase files the tests use.
fn workspace() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("pass"), format!("{PASSPHRASE}\n")).unwrap();
    fs::write(directory.path().join("other"), format!("{OTHER}\n")).unwrap();
    directory
}

#[test]
fn a_new_key_is_sealed_by_default_and_opens_only_with_its_passphrase() {
    let directory = workspace();
    let directory = directory.path();
    // With no passphrase source and no terminal, nothing is written.
    let refused = failure(directory, &["root", "--out", "root.key"]);
    assert!(refused.contains("not a terminal"), "{refused}");
    assert!(!directory.join("root.key").exists());

    let made = ok(
        directory,
        &["root", "--out", "root.key", "--new-passphrase-file", "pass"],
    );
    let text = fs::read_to_string(directory.join("root.key")).unwrap();
    let words: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(words[..2], ["pso-sealed-key", "ml-dsa-87"], "{text}");
    assert!(words[3].starts_with("5045494f5345414c"), "{text}");
    // The line names the key without the passphrase, as `made` printed it.
    assert!(made.contains(words[2]), "{made} {text}");
    let described = ok(directory, &["key", "public", "root.key"]);
    assert!(described.starts_with(&made), "{described}");
    assert!(described.contains("as recorded in the file"), "{described}");
    let mode = fs::metadata(directory.join("root.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    assert_eq!(
        ok(
            directory,
            &["key", "public", "root.key", "--passphrase-file", "pass"]
        ),
        made
    );
    let wrong = failure(
        directory,
        &["key", "public", "root.key", "--passphrase-file", "other"],
    );
    assert!(wrong.contains("passphrase is wrong"), "{wrong}");
    // The public key file needs no passphrase.
    assert_eq!(ok(directory, &["key", "public", "root.key.pub"]), made);
}

#[test]
fn a_short_passphrase_seals_nothing() {
    let directory = workspace();
    let directory = directory.path();
    fs::write(directory.join("short"), "too short\n").unwrap();
    let refused = failure(
        directory,
        &[
            "key",
            "new",
            "--out",
            "k.key",
            "--new-passphrase-file",
            "short",
        ],
    );
    assert!(refused.contains("needs at least 15"), "{refused}");
    assert!(!directory.join("k.key").exists());
    assert!(!directory.join("k.key.pub").exists());
}

#[test]
fn a_sealed_chain_signs_and_verifies() {
    let directory = workspace();
    let directory = directory.path();
    ok(
        directory,
        &["root", "--out", "root.key", "--new-passphrase-file", "pass"],
    );
    ok(
        directory,
        &[
            "cert",
            "top-level",
            "--name",
            "Top",
            "--root-key",
            "root.key",
            "--passphrase-file",
            "pass",
            "--new-key",
            "top.key",
            "--new-passphrase-file",
            "other",
            "--warrant",
            "Delegate=1",
            "--warrant",
            "Name=example.com",
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
            "Signing",
            "--issuer",
            "top.cert",
            "--issuer-key",
            "top.key",
            "--passphrase-file",
            "other",
            "--new-key",
            "signer.key",
            "--new-passphrase-file",
            "pass",
            "--warrant",
            "Name=example.com",
            "--out",
            "signer.cert",
        ],
    );
    fs::write(directory.join("file"), "bytes").unwrap();
    ok(
        directory,
        &[
            "sign",
            "file",
            "--issuer",
            "signer.cert",
            "--issuer-key",
            "signer.key",
            "--passphrase-file",
            "pass",
            "--name",
            "example.com",
        ],
    );
    let store = directory.join("sys/usr/share/pso/toplevel");
    fs::create_dir_all(&store).unwrap();
    let hash = ok(directory, &["hash", "top.cert"]);
    fs::copy(directory.join("top.cert"), store.join(hash.trim())).unwrap();
    let verified = ok(
        directory,
        &[
            "verify",
            "file",
            "--bundle",
            "file.pso",
            "--root",
            "root.key.pub",
            "--store",
            "sys",
        ],
    );
    assert!(verified.starts_with("rooted\n"), "{verified}");
}

#[test]
fn a_plain_key_still_opens_and_can_be_sealed_in_place() {
    let directory = workspace();
    let directory = directory.path();
    let made = ok(
        directory,
        &["key", "new", "--out", "k.key", "--no-passphrase"],
    );
    assert!(
        fs::read_to_string(directory.join("k.key"))
            .unwrap()
            .starts_with("pso-secret-key ")
    );
    // A plain key opens with no passphrase, whatever sources are given.
    assert_eq!(
        ok(
            directory,
            &["key", "public", "k.key", "--passphrase-file", "other"]
        ),
        made
    );

    ok(
        directory,
        &["key", "encrypt", "k.key", "--new-passphrase-file", "pass"],
    );
    assert!(
        fs::read_to_string(directory.join("k.key"))
            .unwrap()
            .starts_with("pso-sealed-key ")
    );
    assert!(!directory.join("k.key.new").exists());
    assert_eq!(
        ok(
            directory,
            &["key", "public", "k.key", "--passphrase-file", "pass"]
        ),
        made
    );

    let again = failure(
        directory,
        &["key", "encrypt", "k.key", "--new-passphrase-file", "pass"],
    );
    assert!(again.contains("already sealed"), "{again}");
}

#[test]
fn a_passphrase_is_changed_in_place_and_the_old_one_stops_working() {
    let directory = workspace();
    let directory = directory.path();
    let made = ok(
        directory,
        &[
            "key",
            "new",
            "--out",
            "k.key",
            "--new-passphrase-file",
            "pass",
        ],
    );
    ok(
        directory,
        &[
            "key",
            "passphrase",
            "k.key",
            "--passphrase-file",
            "pass",
            "--new-passphrase-file",
            "other",
        ],
    );
    assert_eq!(
        ok(
            directory,
            &["key", "public", "k.key", "--passphrase-file", "other"]
        ),
        made
    );
    failure(
        directory,
        &["key", "public", "k.key", "--passphrase-file", "pass"],
    );

    // A wrong current passphrase changes nothing.
    let before = fs::read(directory.join("k.key")).unwrap();
    failure(
        directory,
        &[
            "key",
            "passphrase",
            "k.key",
            "--passphrase-file",
            "pass",
            "--new-passphrase-file",
            "pass",
        ],
    );
    assert_eq!(fs::read(directory.join("k.key")).unwrap(), before);
}

#[test]
fn a_passphrase_is_read_from_a_descriptor() {
    let directory = workspace();
    let directory = directory.path();
    let made = ok(
        directory,
        &[
            "key",
            "new",
            "--out",
            "k.key",
            "--new-passphrase-file",
            "pass",
        ],
    );
    // The shell opens the file on descriptor 3 and pso reads it there.
    let output = Command::new("sh")
        .current_dir(directory)
        .args([
            "-c",
            "exec \"$0\" key public k.key --passphrase-fd 3 3<pass",
        ])
        .arg(env!("CARGO_BIN_EXE_pso"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), made);
}

#[test]
fn a_sealed_key_whose_line_names_another_key_is_refused() {
    let directory = workspace();
    let directory = directory.path();
    ok(
        directory,
        &[
            "key",
            "new",
            "--out",
            "a.key",
            "--new-passphrase-file",
            "pass",
        ],
    );
    ok(
        directory,
        &[
            "key",
            "new",
            "--out",
            "b.key",
            "--new-passphrase-file",
            "pass",
        ],
    );
    let a = fs::read_to_string(directory.join("a.key")).unwrap();
    let b = fs::read_to_string(directory.join("b.key")).unwrap();
    let a: Vec<&str> = a.split_whitespace().collect();
    let b: Vec<&str> = b.split_whitespace().collect();
    // a's blob under b's key hash.
    fs::write(
        directory.join("a.key"),
        format!("{} {} {} {}\n", a[0], a[1], b[2], a[3]),
    )
    .unwrap();
    let refused = failure(
        directory,
        &["key", "public", "a.key", "--passphrase-file", "pass"],
    );
    assert!(refused.contains("not the one the file names"), "{refused}");
}

#[test]
fn a_sealed_key_whose_type_disagrees_with_its_line_is_refused() {
    let directory = workspace();
    let directory = directory.path();
    ok(
        directory,
        &[
            "key",
            "new",
            "--out",
            "k.key",
            "--new-passphrase-file",
            "pass",
        ],
    );
    let text = fs::read_to_string(directory.join("k.key")).unwrap();
    fs::write(
        directory.join("k.key"),
        text.replace(" ml-dsa-65 ", " ml-dsa-87 "),
    )
    .unwrap();
    let refused = failure(
        directory,
        &["key", "public", "k.key", "--passphrase-file", "pass"],
    );
    assert!(refused.contains("the sealed key is ml-dsa-65"), "{refused}");
}
