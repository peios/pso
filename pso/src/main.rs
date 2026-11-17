//! The `pso` command: make keys and roots, issue certificates, sign files,
//! revoke, and verify.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

use pso::core::{
    Bundle, Certificate, Crypto, Distrust, HashForm, Key, KeyType, Kind, Leaf, Outcome, Refusal,
    Revocation, Role, RustCrypto, TargetType, Verified, Verifier, Warrant, WarrantType,
    encode_bundle,
};
use pso::keys::{self, SecretKey};
use pso::place::{self, Search};
use pso::store::{self, DirectoryLookup};
use pso::{hex, issue};

/// What a public key file's name adds to its secret key file's.
const PUBLIC_SUFFIX: &str = ".pub";
/// Warrants whose form a Peios specification fixes, so that naming one is
/// enough: each is a plain flag that a child can hold unchanged.
const KNOWN_FLAGS: &[&str] = &["Revoke", "Repository", "TrustStore"];

#[derive(Parser)]
#[command(name = "pso", version, about = "Peios Signed Objects")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a root: a key that signs top-level certificates
    Root(NewKey),
    /// Make a key, or show a key's public half
    #[command(subcommand)]
    Key(KeyCommand),
    /// Issue a certificate
    #[command(subcommand)]
    Cert(CertCommand),
    /// Sign a file
    Sign(Sign),
    /// Verify a file
    Verify(Verify),
    /// Revoke a certificate or a leaf
    Revoke(Revoke),
    /// Write a distrust entry for a certificate or a leaf
    Distrust(DistrustArgs),
    /// Show what an object holds
    Show { object: PathBuf },
    /// Print an object's hash, which is its name in the trust store
    Hash { object: PathBuf },
    /// Show what the trust store beneath a root directory enables
    Store(StoreArgs),
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Make a key
    New(NewKey),
    /// Print the type and key hash of a key, from its secret or its public key file
    Public { key: PathBuf },
}

#[derive(Args)]
struct NewKey {
    /// The key's type [default: ml-dsa-87 for a root, ml-dsa-65 otherwise]
    #[arg(long = "type", value_name = "TYPE")]
    key_type: Option<String>,
    /// Where the secret key goes; the public key goes beside it, with .pub added
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

#[derive(Subcommand)]
enum CertCommand {
    /// Issue a top-level, signed by a root or by itself
    TopLevel(TopLevel),
    /// Issue an intermediary beneath a certificate
    Intermediary(Intermediary),
}

#[derive(Args)]
struct TopLevel {
    /// A description of the holder, for a person
    #[arg(long)]
    name: String,
    /// The root's secret key, to sign with
    #[arg(long, value_name = "SECRET", conflicts_with = "self_signed")]
    root_key: Option<PathBuf>,
    #[command(flatten)]
    subject: Subject,
    /// The certificate's own secret key, to sign itself with
    #[arg(long, value_name = "SECRET", conflicts_with_all = ["key", "new_key"])]
    self_signed: Option<PathBuf>,
    /// A warrant the certificate holds; repeat for each
    #[arg(long = "warrant", value_name = "WARRANT")]
    warrants: Vec<String>,
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

/// The key a certificate is for: one that exists, or one made for it.
#[derive(Args)]
struct Subject {
    /// The public key the certificate is for, where someone else holds its secret key
    #[arg(long, value_name = "PUBLIC", conflicts_with = "new_key")]
    key: Option<PathBuf>,
    /// Make a key for the certificate: its secret key goes here, and its
    /// public key beside it, with .pub added
    #[arg(long, value_name = "FILE")]
    new_key: Option<PathBuf>,
    /// The type of the key --new-key makes
    #[arg(
        long,
        value_name = "TYPE",
        default_value = "ml-dsa-65",
        requires = "new_key"
    )]
    key_type: String,
}

impl Subject {
    /// The public key the certificate is for, and the secret key to save
    /// once the certificate is issued, if one was made.
    fn resolve(&self) -> Result<(Key, Option<(SecretKey, &Path)>)> {
        match (&self.key, &self.new_key) {
            (Some(public), None) => Ok((keys::load_public(public)?, None)),
            (None, Some(path)) => {
                if path.exists() {
                    bail!("{}: exists, and a key is never replaced", path.display());
                }
                let secret = SecretKey::generate(keys::key_type_from_name(&self.key_type)?)?;
                Ok((secret.public(), Some((secret, path))))
            }
            _ => bail!("give --key or --new-key"),
        }
    }
}

#[derive(Args)]
struct Intermediary {
    /// A description of the holder, for a person
    #[arg(long)]
    name: String,
    #[command(flatten)]
    subject: Subject,
    /// The issuing certificate
    #[arg(long, value_name = "CERTIFICATE")]
    issuer: PathBuf,
    /// The issuing certificate's secret key
    #[arg(long, value_name = "SECRET")]
    issuer_key: PathBuf,
    /// A warrant the certificate holds; repeat for each
    #[arg(long = "warrant", value_name = "WARRANT")]
    warrants: Vec<String>,
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum Place {
    /// A file beside the signed one, with .pso added
    Detached,
    /// The security.pso extended attribute
    Attribute,
    /// The .pso section of an ELF object, which must be reserved already
    Section,
}

#[derive(Args)]
struct Sign {
    file: PathBuf,
    /// The issuing certificate
    #[arg(long, value_name = "CERTIFICATE")]
    issuer: PathBuf,
    /// The issuing certificate's secret key
    #[arg(long, value_name = "SECRET")]
    issuer_key: PathBuf,
    /// The name the leaf is issued under, within the issuer's Name warrant
    #[arg(long)]
    name: String,
    /// A warrant the leaf requests; repeat for each
    #[arg(long = "warrant", value_name = "WARRANT")]
    warrants: Vec<String>,
    /// A certificate to carry beyond the issuer, in order upward; repeat for each
    #[arg(long = "carry", value_name = "CERTIFICATE")]
    carry: Vec<PathBuf>,
    /// Carry only the leaf, and leave the issuer to be found by its hash
    #[arg(long, conflicts_with = "carry")]
    leaf_only: bool,
    /// Where the bundle goes
    #[arg(long, value_enum, default_value = "detached")]
    place: Place,
    /// Print the size the bundle will be, and sign nothing
    #[arg(long)]
    size: bool,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, ValueEnum)]
enum Require {
    Consistent,
    Unrooted,
    Rooted,
}

#[derive(Args)]
struct Verify {
    file: PathBuf,
    /// A detached bundle, in place of one the file carries
    #[arg(long, value_name = "FILE")]
    bundle: Option<PathBuf>,
    /// A root's public key; repeat for each
    #[arg(long = "root", value_name = "PUBLIC")]
    roots: Vec<PathBuf>,
    /// The root directory of the system whose trust store is used
    #[arg(long, value_name = "DIRECTORY", default_value = "/")]
    store: PathBuf,
    /// The directory intermediaries are found in
    /// [default: usr/share/pso/intermediate beneath --store]
    #[arg(long, value_name = "DIRECTORY")]
    intermediates: Option<PathBuf>,
    /// A warrant the caller acts on, so that Must Understand is satisfied; repeat for each
    #[arg(long = "recognize", value_name = "NAME")]
    recognized: Vec<String>,
    /// The least result that succeeds
    #[arg(long, value_enum, default_value = "rooted")]
    require: Require,
}

#[derive(Args)]
struct Revoke {
    /// The certificate, leaf or bundle to revoke; a bundle's leaf is what is revoked
    target: PathBuf,
    /// The certificate that signs the revocation: the target or one above it
    #[arg(
        long,
        value_name = "CERTIFICATE",
        requires = "signer_key",
        conflicts_with = "root_key"
    )]
    signer: Option<PathBuf>,
    /// The signing certificate's secret key
    #[arg(long, value_name = "SECRET")]
    signer_key: Option<PathBuf>,
    /// The root's secret key, to revoke a top-level it signed
    #[arg(long, value_name = "SECRET")]
    root_key: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

#[derive(Args)]
struct DistrustArgs {
    /// The certificate, leaf or bundle to distrust; a bundle's leaf is what is distrusted
    target: PathBuf,
    /// The directory the entry goes in, named by the hash it distrusts
    #[arg(long, value_name = "DIRECTORY")]
    out_dir: PathBuf,
}

#[derive(Args)]
struct StoreArgs {
    /// The root directory of the system
    #[arg(default_value = "/")]
    root: PathBuf,
    /// A root's public key; repeat for each
    #[arg(long = "root", value_name = "PUBLIC")]
    roots: Vec<PathBuf>,
    /// Write the store image a kernel reads at boot, and list nothing
    #[arg(long, value_name = "FILE")]
    image: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("pso: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Root(new) => new_key(&new, KeyType::MlDsa87)?,
        Command::Key(KeyCommand::New(new)) => new_key(&new, KeyType::MlDsa65)?,
        Command::Key(KeyCommand::Public { key }) => print_public(&public_of(&key)?),
        Command::Cert(CertCommand::TopLevel(args)) => top_level(&args)?,
        Command::Cert(CertCommand::Intermediary(args)) => intermediary(&args)?,
        Command::Sign(args) => sign(&args)?,
        Command::Verify(args) => return verify(&args),
        Command::Revoke(args) => revoke(&args)?,
        Command::Distrust(args) => distrust(&args)?,
        Command::Show { object } => show(&read(&object)?)?,
        Command::Hash { object } => {
            println!("{}", hex::encode(&RustCrypto.sha512(&[&read(&object)?])))
        }
        Command::Store(args) => show_store(&args)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// Writes `bytes` to a new file at `path`. A file already there is never
/// replaced: an object is named by its hash or kept for good.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .with_context(|| format!("writing {}", path.display()))
}

/// Writes `bytes` to `path` in one step, so that a reader never finds a
/// partial file: the image is written beside where it goes and renamed.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    let beside = PathBuf::from(beside);
    fs::write(&beside, bytes).with_context(|| format!("writing {}", beside.display()))?;
    fs::rename(&beside, path).with_context(|| format!("writing {}", path.display()))
}

fn new_key(new: &NewKey, default_type: KeyType) -> Result<()> {
    let key_type = match &new.key_type {
        Some(name) => keys::key_type_from_name(name)?,
        None => default_type,
    };
    let secret = SecretKey::generate(key_type)?;
    save_key_pair(&secret, &new.out)?;
    print_public(&secret.public());
    Ok(())
}

/// Writes `secret` to a new file at `path`, and its public key beside it.
fn save_key_pair(secret: &SecretKey, path: &Path) -> Result<()> {
    let mut public_path = path.to_owned().into_os_string();
    public_path.push(PUBLIC_SUFFIX);
    secret.save(path)?;
    write_new(
        Path::new(&public_path),
        keys::format_public(&secret.public()).as_bytes(),
    )
}

/// Writes a certificate and, if a key was made for it, the key. The
/// certificate is issued before anything is written, so a refusal leaves
/// no key behind.
fn save_certificate(
    out: &Path,
    certificate: &Certificate,
    made: Option<(SecretKey, &Path)>,
) -> Result<()> {
    if out.exists() {
        bail!(
            "{}: exists, and a certificate is never replaced",
            out.display()
        );
    }
    if let Some((secret, path)) = made {
        save_key_pair(&secret, path)?;
    }
    write_new(out, certificate.bytes())?;
    println!("{}", hex::encode(&certificate.hash(&RustCrypto)));
    Ok(())
}

/// The public key that the key file at `path` holds or, for a secret key
/// file, gives.
fn public_of(path: &Path) -> Result<Key> {
    match keys::load_public(path) {
        Ok(key) => Ok(key),
        Err(_) => Ok(SecretKey::load(path)
            .map_err(|_| anyhow!("{}: not a key file", path.display()))?
            .public()),
    }
}

fn print_public(key: &Key) {
    println!("type      {}", key.key_type.name());
    println!("key hash  {}", hex::encode(&key.hash(&RustCrypto)));
}

fn certificate(path: &Path) -> Result<Certificate> {
    Certificate::decode(&read(path)?)
        .map_err(|error| anyhow!("{}: not a certificate: {error:?}", path.display()))
}

fn top_level(args: &TopLevel) -> Result<()> {
    let warrants = parse_warrants(&args.warrants)?;
    let (certificate, made) = match (&args.root_key, &args.self_signed) {
        (Some(root), None) => {
            let (subject, made) = args.subject.resolve()?;
            let root = SecretKey::load(root)?;
            (
                issue::top_level_under_root(&root, &args.name, &subject, warrants)?,
                made,
            )
        }
        (None, Some(own)) => (
            issue::top_level_self_signed(&SecretKey::load(own)?, &args.name, warrants)?,
            None,
        ),
        // A new key with no root to sign for it signs itself.
        (None, None) if args.subject.new_key.is_some() => {
            let (_, made) = args.subject.resolve()?;
            let (secret, path) = made.expect("--new-key makes a key");
            let certificate = issue::top_level_self_signed(&secret, &args.name, warrants)?;
            (certificate, Some((secret, path)))
        }
        _ => bail!(
            "give --root-key, --self-signed, or --new-key alone to make a key that signs itself"
        ),
    };
    save_certificate(&args.out, &certificate, made)
}

fn intermediary(args: &Intermediary) -> Result<()> {
    let (subject, made) = args.subject.resolve()?;
    let certificate = issue::intermediary(
        &certificate(&args.issuer)?,
        &SecretKey::load(&args.issuer_key)?,
        &args.name,
        &subject,
        parse_warrants(&args.warrants)?,
    )?;
    save_certificate(&args.out, &certificate, made)
}

fn sign(args: &Sign) -> Result<()> {
    let issuer = certificate(&args.issuer)?;
    let key = SecretKey::load(&args.issuer_key)?;
    let warrants = parse_warrants(&args.warrants)?;
    let hash_form = match args.place {
        Place::Section => HashForm::Elf,
        Place::Detached | Place::Attribute => HashForm::WholeFile,
    };
    let mut carried: Vec<Vec<u8>> = Vec::new();
    if !args.leaf_only {
        carried.push(issuer.bytes().to_vec());
        for path in &args.carry {
            carried.push(certificate(path)?.bytes().to_vec());
        }
    }
    let assemble = |content_hash| -> Result<Vec<u8>> {
        let leaf = issue::leaf(
            &issuer,
            &key,
            hash_form,
            content_hash,
            &args.name,
            warrants.clone(),
        )?;
        let carried: Vec<&[u8]> = carried.iter().map(Vec::as_slice).collect();
        encode_bundle(leaf.bytes(), &carried).map_err(|e| anyhow!("the bundle is malformed: {e:?}"))
    };

    // A bundle's length does not depend on the content hash, so signing a
    // hash of zeros gives the length to reserve.
    let len = assemble([0u8; 64])?.len();
    if args.size {
        println!("{len}");
        return Ok(());
    }
    if let Place::Section = args.place {
        match place::bundle_section(&args.file)? {
            Some(section) if section.len == len as u64 => {}
            Some(section) => bail!(
                "{}: its {} section is {} bytes; reserve {len}",
                args.file.display(),
                place::SECTION,
                section.len
            ),
            None => bail!(
                "{}: has no {} section; reserve one of {len} bytes",
                args.file.display(),
                place::SECTION
            ),
        }
    }
    let bundle = assemble(place::content_hash(&args.file, hash_form)?)?;
    match args.place {
        Place::Detached => {
            let path = place::detached_path(&args.file);
            fs::write(&path, &bundle).with_context(|| format!("writing {}", path.display()))?;
        }
        Place::Attribute => place::set_attribute(&args.file, place::ATTRIBUTE, &bundle)?,
        Place::Section => place::write_section(&args.file, &bundle)?,
    }
    Ok(())
}

fn load_roots(paths: &[PathBuf]) -> Result<Vec<Key>> {
    paths.iter().map(|path| keys::load_public(path)).collect()
}

fn verify(args: &Verify) -> Result<ExitCode> {
    let roots = load_roots(&args.roots)?;
    let loaded = store::load(&args.store, &roots)?;
    let found = match &args.bundle {
        Some(path) => place::Found {
            bundle: read(path)?,
            hash_form: HashForm::WholeFile,
        },
        None => match place::find(&args.file)? {
            Search::Found(found) => found,
            Search::Unsigned => {
                println!("unsigned");
                return Ok(ExitCode::FAILURE);
            }
            Search::Unusable(why) => {
                println!("invalid");
                println!("  {why}");
                return Ok(ExitCode::FAILURE);
            }
        },
    };
    let content_hash = place::content_hash(&args.file, found.hash_form)?;
    let recognized: Vec<&str> = args.recognized.iter().map(String::as_str).collect();
    let verifier = Verifier {
        crypto: &RustCrypto,
        roots: &roots,
        store: &loaded.store,
        recognized: &recognized,
    };
    let intermediates = args
        .intermediates
        .clone()
        .unwrap_or_else(|| args.store.join(store::PACKAGE_INTERMEDIARIES));
    let outcome = verifier
        .verify(
            &found.bundle,
            found.hash_form,
            &content_hash,
            &mut DirectoryLookup::new(intermediates),
        )
        .map_err(|_| anyhow!("the signature could not be checked"))?;

    println!("{}", outcome.name());
    let reached = match &outcome {
        Outcome::Invalid(why) => {
            println!("  {why:?}");
            None
        }
        Outcome::Incomplete { missing } => {
            println!("  missing {}", hex::encode(missing));
            None
        }
        Outcome::Refused(Refusal::Revoked) => {
            println!("  revoked");
            None
        }
        Outcome::Refused(Refusal::Distrusted) => {
            println!("  distrusted");
            None
        }
        Outcome::Consistent(verified) => Some((Require::Consistent, verified)),
        Outcome::Unrooted(verified) => Some((Require::Unrooted, verified)),
        Outcome::Rooted(verified) => Some((Require::Rooted, verified)),
    };
    let Some((reached, verified)) = reached else {
        return Ok(ExitCode::FAILURE);
    };
    print_verified(verified);
    Ok(if reached >= args.require {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn print_verified(verified: &Verified) {
    println!("  name       {}", verified.name);
    println!("  top-level  {}", hex::encode(&verified.top_level));
    if let Some(root) = &verified.root {
        println!("  root       {}", hex::encode(root));
    }
    for warrant in &verified.warrants {
        println!("  warrant    {}", describe_warrant(warrant));
    }
}

/// What `path` holds that can be revoked or distrusted: a certificate, or
/// a leaf, which a bundle stands for.
fn target(path: &Path) -> Result<(TargetType, [u8; 64], Option<Certificate>)> {
    let bytes = read(path)?;
    let malformed = |error| anyhow!("{}: malformed: {error:?}", path.display());
    match Kind::of(&bytes).map_err(malformed)? {
        Kind::Certificate => {
            let certificate = Certificate::decode(&bytes).map_err(malformed)?;
            Ok((
                TargetType::Certificate,
                certificate.hash(&RustCrypto),
                Some(certificate),
            ))
        }
        Kind::Leaf => Ok((
            TargetType::Leaf,
            Leaf::decode(&bytes).map_err(malformed)?.hash(&RustCrypto),
            None,
        )),
        Kind::Bundle => {
            let bundle = Bundle::decode(&bytes).map_err(malformed)?;
            Ok((TargetType::Leaf, bundle.leaf.hash(&RustCrypto), None))
        }
        _ => bail!("{}: not a certificate, a leaf or a bundle", path.display()),
    }
}

fn revoke(args: &Revoke) -> Result<()> {
    let (target_type, hash, as_certificate) = target(&args.target)?;
    let revocation = match (&args.signer, &args.signer_key, &args.root_key) {
        (Some(signer), Some(key), None) => issue::revocation_by_certificate(
            &certificate(signer)?,
            &SecretKey::load(key)?,
            target_type,
            hash,
        )?,
        (None, None, Some(root)) => {
            let top_level = as_certificate
                .ok_or_else(|| anyhow!("a root revokes only a top-level it signed"))?;
            issue::revocation_by_root(&SecretKey::load(root)?, &top_level)?
        }
        _ => bail!("give --signer with --signer-key, or --root-key"),
    };
    write_new(&args.out, revocation.bytes())?;
    println!("{}", hex::encode(&revocation.hash(&RustCrypto)));
    Ok(())
}

fn distrust(args: &DistrustArgs) -> Result<()> {
    let (target_type, hash, _) = target(&args.target)?;
    let path = args.out_dir.join(hex::encode(&hash));
    write_new(
        &path,
        &Distrust {
            target_type,
            target: hash,
        }
        .encode(),
    )?;
    println!("{}", path.display());
    Ok(())
}

fn show(bytes: &[u8]) -> Result<()> {
    let malformed = |error| anyhow!("malformed: {error:?}");
    match Kind::of(bytes).map_err(malformed)? {
        Kind::Certificate => show_certificate(&Certificate::decode(bytes).map_err(malformed)?, ""),
        Kind::Leaf => show_leaf(&Leaf::decode(bytes).map_err(malformed)?, ""),
        Kind::Bundle => {
            let bundle = Bundle::decode(bytes).map_err(malformed)?;
            println!("bundle");
            println!("  size       {} bytes", bytes.len());
            show_leaf(&bundle.leaf, "  ");
            for certificate in &bundle.certificates {
                show_certificate(certificate, "  ");
            }
        }
        Kind::Revocation => {
            let revocation = Revocation::decode(bytes).map_err(malformed)?;
            println!("revocation");
            println!(
                "  hash       {}",
                hex::encode(&revocation.hash(&RustCrypto))
            );
            println!(
                "  target     {} {}",
                target_name(revocation.body.target_type),
                hex::encode(&revocation.body.target)
            );
            println!("  signer     {}", hex::encode(&revocation.body.signer));
        }
        Kind::Distrust => {
            let entry = Distrust::decode(bytes).map_err(malformed)?;
            println!("distrust");
            println!(
                "  target     {} {}",
                target_name(entry.target_type),
                hex::encode(&entry.target)
            );
        }
        Kind::StoreImage => bail!("a store image, which this command does not read"),
    }
    Ok(())
}

fn target_name(target_type: TargetType) -> &'static str {
    match target_type {
        TargetType::Certificate => "certificate",
        TargetType::Leaf => "leaf",
    }
}

fn show_certificate(certificate: &Certificate, indent: &str) {
    let body = &certificate.body;
    let role = match body.role {
        Role::TopLevel => "top-level",
        Role::Intermediary => "intermediary",
    };
    println!("{indent}certificate");
    println!(
        "{indent}  hash       {}",
        hex::encode(&certificate.hash(&RustCrypto))
    );
    println!("{indent}  role       {role}");
    println!("{indent}  name       {}", body.name);
    println!(
        "{indent}  key        {} {}",
        body.key.key_type.name(),
        hex::encode(&body.key.hash(&RustCrypto))
    );
    let self_signed = body.role == Role::TopLevel && body.issuer == body.key.hash(&RustCrypto);
    let issuer = if self_signed { " (itself)" } else { "" };
    println!("{indent}  issuer     {}{issuer}", hex::encode(&body.issuer));
    for warrant in &body.warrants {
        println!("{indent}  warrant    {}", describe_warrant(warrant));
    }
}

fn show_leaf(leaf: &Leaf, indent: &str) {
    let body = &leaf.body;
    let form = match body.hash_form {
        HashForm::WholeFile => "whole file",
        HashForm::Elf => "ELF",
    };
    println!("{indent}leaf");
    println!(
        "{indent}  hash       {}",
        hex::encode(&leaf.hash(&RustCrypto))
    );
    println!("{indent}  name       {}", body.name);
    println!(
        "{indent}  content    {form} {}",
        hex::encode(&body.content_hash)
    );
    println!("{indent}  issuer     {}", hex::encode(&body.issuer));
    for warrant in &body.warrants {
        println!("{indent}  warrant    {}", describe_warrant(warrant));
    }
}

fn describe_warrant(warrant: &Warrant) -> String {
    let value = match warrant.warrant_type() {
        WarrantType::Limit => warrant
            .limit_value()
            .map(|limit| limit.to_string())
            .unwrap_or_default(),
        WarrantType::Set | WarrantType::Namespace => warrant
            .elements()
            .map(|element| String::from_utf8_lossy(element).into_owned())
            .collect::<Vec<_>>()
            .join(","),
    };
    let must = if warrant.is_must_understand() {
        " (must understand)"
    } else {
        ""
    };
    if value.is_empty() {
        format!("{}{must}", warrant.name())
    } else {
        format!("{}={value}{must}", warrant.name())
    }
}

fn show_store(args: &StoreArgs) -> Result<()> {
    let roots = load_roots(&args.roots)?;
    let loaded = store::load(&args.root, &roots)?;
    if let Some(path) = &args.image {
        let image = loaded
            .store
            .to_image()
            .map_err(|e| anyhow!("the store is too large: {e:?}"))?;
        return replace(path, &image);
    }
    for hash in loaded.store.enabled() {
        println!("enabled      {}", hex::encode(hash));
    }
    for hash in &loaded.quarantined {
        println!("quarantined  {}", hex::encode(hash));
    }
    println!("revocations  {}", loaded.store.revocations.len());
    println!("distrust     {}", loaded.store.distrust.len());
    for (path, why) in &loaded.ignored {
        println!("ignored      {} {why}", path.display());
    }
    Ok(())
}

/// The warrants the command line gives. Each is one of:
///
/// - `Delegate=<depth>`, `Name=<name>[,<name>…]`, or a flag this command
///   knows, such as `Revoke` or `Repository`;
/// - `[strict+][must+]<type>:<name>[=<value>]`, for any other, where
///   `<type>` is `set`, `namespace` or `limit`, `strict` means a child's
///   value must be narrower, and `must` marks it Must Understand.
fn parse_warrants(specs: &[String]) -> Result<Vec<Warrant>> {
    specs
        .iter()
        .map(|spec| parse_warrant(spec).with_context(|| format!("warrant {spec}")))
        .collect()
}

fn parse_warrant(spec: &str) -> Result<Warrant> {
    let malformed = |error| anyhow!("malformed: {error:?}");
    let (head, value) = match spec.split_once('=') {
        Some((head, value)) => (head, Some(value)),
        None => (spec, None),
    };
    let elements: Vec<&str> = value
        .map(|value| value.split(',').collect())
        .unwrap_or_default();
    let Some((kind, name)) = head.split_once(':') else {
        return match (head, value) {
            ("Delegate", Some(depth)) => Ok(Warrant::delegate(
                depth.parse().context("a depth is a number")?,
            )),
            ("Name", Some(_)) => Warrant::name_warrant(&elements).map_err(malformed),
            (flag, None) if KNOWN_FLAGS.contains(&flag) => {
                Warrant::set(flag, &[], true).map_err(malformed)
            }
            _ => bail!("not a warrant this command knows; write it as <type>:<name>[=<value>]"),
        };
    };
    let mut allow_equal = true;
    let mut must_understand = false;
    let mut warrant_type = None;
    for word in kind.split('+') {
        match word {
            "strict" => allow_equal = false,
            "must" => must_understand = true,
            "set" | "namespace" | "limit" if warrant_type.is_none() => warrant_type = Some(word),
            _ => bail!("unknown word {word}"),
        }
    }
    let warrant = match warrant_type {
        Some("set") => Warrant::set(name, &elements, allow_equal),
        Some("namespace") => Warrant::namespace(name, &elements, allow_equal),
        Some("limit") => {
            let limit = value.ok_or_else(|| anyhow!("a limit needs a value"))?;
            Warrant::limit(
                name,
                limit.parse().context("a limit is a number")?,
                allow_equal,
            )
        }
        _ => bail!("give a type: set, namespace or limit"),
    }
    .map_err(malformed)?;
    Ok(if must_understand {
        warrant.must_understand()
    } else {
        warrant
    })
}
