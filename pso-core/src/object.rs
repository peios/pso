//! The objects of PSO and their encoding: certificates, leaves, bundles,
//! revocations and distrust entries (§7.4, §7.6 to §7.8, §7.12, §7.13).

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::{Crypto, Hash, Key, KeyType};
use crate::warrant::{self, Warrant, valid_leaf_name};
use crate::wire::{Reader, put_long_field, put_short_field};

/// The format version this crate implements.
pub const FORMAT_VERSION: u8 = 0x01;
/// The most intermediaries a chain can hold between its leaf and its
/// top-level.
pub const MAX_INTERMEDIARIES: usize = 16;
/// The most certificates a bundle can carry: every intermediary and the
/// top-level.
pub const MAX_BUNDLE_CERTIFICATES: usize = MAX_INTERMEDIARIES + 1;
/// The largest bundle, which is the largest value an extended attribute
/// can hold.
pub const MAX_BUNDLE_LEN: usize = 65_536;
/// The largest certificate a verifier reads when it finds one by its hash.
pub const MAX_FOUND_CERTIFICATE_LEN: usize = 65_535;

const MAGIC: &[u8; 3] = b"PSO";
const HEADER_RESERVED: u8 = 0x00;

/// Why an object does not decode exactly as its layout gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    Truncated,
    TrailingBytes,
    BadMagic,
    UnknownVersion,
    ReservedSet,
    WrongKind,
    UnknownKeyType,
    WrongKeyLength,
    UnknownRole,
    UnknownHashForm,
    UnknownTargetType,
    BadName,
    BadWarrant,
    WarrantOrder,
    TooManyWarrants,
    BadSignatureLength,
    FieldTooLong,
    TooManyCertificates,
    TooLarge,
}

/// What an object is: the `kind` byte of its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Certificate,
    Leaf,
    Bundle,
    Revocation,
    Distrust,
    /// The trust store image, which PSPK §6.3 defines.
    StoreImage,
}

impl Kind {
    pub fn byte(self) -> u8 {
        match self {
            Self::Certificate => 0x01,
            Self::Leaf => 0x02,
            Self::Bundle => 0x03,
            Self::Revocation => 0x04,
            Self::Distrust => 0x05,
            Self::StoreImage => 0x06,
        }
    }

    /// The kind of the object in `bytes`, from its header alone.
    pub fn of(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut reader = Reader::new(bytes);
        let kind = read_header(&mut reader)?;
        [
            Self::Certificate,
            Self::Leaf,
            Self::Bundle,
            Self::Revocation,
            Self::Distrust,
            Self::StoreImage,
        ]
        .into_iter()
        .find(|known| known.byte() == kind)
        .ok_or(Malformed::WrongKind)
    }
}

/// Reads a header and returns its `kind` byte.
fn read_header(reader: &mut Reader<'_>) -> Result<u8, Malformed> {
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(Malformed::BadMagic);
    }
    let kind = reader.u8()?;
    if reader.u8()? != FORMAT_VERSION {
        return Err(Malformed::UnknownVersion);
    }
    if reader.u8()? != HEADER_RESERVED {
        return Err(Malformed::ReservedSet);
    }
    Ok(kind)
}

fn expect_header(reader: &mut Reader<'_>, kind: Kind) -> Result<(), Malformed> {
    if read_header(reader)? == kind.byte() {
        Ok(())
    } else {
        Err(Malformed::WrongKind)
    }
}

fn put_header(out: &mut Vec<u8>, kind: Kind) {
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[kind.byte(), FORMAT_VERSION, HEADER_RESERVED]);
}

/// The signature at the end of a signed object. Its algorithm is the
/// issuer's, which is not known while decoding, so only a length that no
/// key type gives is refused here.
fn read_signature(reader: &mut Reader<'_>) -> Result<Vec<u8>, Malformed> {
    let signature = reader.rest();
    let known = [KeyType::MlDsa65, KeyType::MlDsa87];
    if known
        .iter()
        .any(|key_type| key_type.signature_len() == signature.len())
    {
        Ok(signature.to_vec())
    } else {
        Err(Malformed::BadSignatureLength)
    }
}

/// Whether a certificate heads a chain or was issued within one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    TopLevel,
    Intermediary,
}

impl Role {
    fn from_byte(byte: u8) -> Result<Self, Malformed> {
        match byte {
            0x01 => Ok(Self::TopLevel),
            0x02 => Ok(Self::Intermediary),
            _ => Err(Malformed::UnknownRole),
        }
    }

    fn byte(self) -> u8 {
        match self {
            Self::TopLevel => 0x01,
            Self::Intermediary => 0x02,
        }
    }
}

/// Everything of a certificate that its signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateBody {
    pub role: Role,
    /// An intermediary's issuing certificate, by object hash. A top-level's
    /// root, or its own key if it is self-signed, by key hash.
    pub issuer: Hash,
    /// A description of the holder for a person. Nothing is decided on it.
    pub name: String,
    pub key: Key,
    pub warrants: Vec<Warrant>,
}

impl CertificateBody {
    /// The bytes an issuer signs.
    pub fn to_be_signed(&self) -> Result<Vec<u8>, Malformed> {
        let printable = self.name.bytes().all(|b| (0x20..=0x7E).contains(&b));
        if self.name.is_empty() || !printable {
            return Err(Malformed::BadName);
        }
        let mut out = Vec::new();
        put_header(&mut out, Kind::Certificate);
        out.push(self.role.byte());
        out.extend_from_slice(&self.issuer);
        put_short_field(&mut out, self.name.as_bytes()).map_err(|_| Malformed::BadName)?;
        out.push(self.key.key_type.byte());
        out.extend_from_slice(&self.key.bytes);
        warrant::encode_all(&self.warrants, &mut out)?;
        Ok(out)
    }
}

/// A certificate: a key bound to a name and a set of warrants (§7.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub body: CertificateBody,
    signature: Vec<u8>,
    bytes: Vec<u8>,
}

impl Certificate {
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut reader = Reader::new(bytes);
        expect_header(&mut reader, Kind::Certificate)?;
        let role = Role::from_byte(reader.u8()?)?;
        let issuer = reader.hash()?;
        let name = reader.short_field()?;
        if name.is_empty() || !name.iter().all(|b| (0x20..=0x7E).contains(b)) {
            return Err(Malformed::BadName);
        }
        let name = String::from_utf8(name.to_vec()).map_err(|_| Malformed::BadName)?;
        let key_type = KeyType::from_byte(reader.u8()?)?;
        let key = Key::new(key_type, reader.take(key_type.key_len())?.to_vec())?;
        let warrants = warrant::decode_all(&mut reader)?;
        let signature = read_signature(&mut reader)?;
        Ok(Self {
            body: CertificateBody {
                role,
                issuer,
                name,
                key,
                warrants,
            },
            signature,
            bytes: bytes.to_vec(),
        })
    }

    /// The certificate `body` describes, signed with `signature`.
    pub fn from_signed(body: &CertificateBody, signature: &[u8]) -> Result<Self, Malformed> {
        let mut bytes = body.to_be_signed()?;
        bytes.extend_from_slice(signature);
        Self::decode(&bytes)
    }

    /// The whole object.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes the signature covers.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() - self.signature.len()]
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The object hash.
    pub fn hash(&self, crypto: &dyn Crypto) -> Hash {
        crypto.sha512(&[&self.bytes])
    }

    pub fn warrant(&self, name: &str) -> Option<&Warrant> {
        warrant::find(&self.body.warrants, name)
    }
}

/// Which bytes of a file a leaf's content hash covers (§7.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashForm {
    /// Every byte of the file.
    WholeFile,
    /// An ELF object with the contents of its signature sections zeroed.
    Elf,
}

impl HashForm {
    pub fn from_byte(byte: u8) -> Result<Self, Malformed> {
        match byte {
            0x01 => Ok(Self::WholeFile),
            0x02 => Ok(Self::Elf),
            _ => Err(Malformed::UnknownHashForm),
        }
    }

    pub fn byte(self) -> u8 {
        match self {
            Self::WholeFile => 0x01,
            Self::Elf => 0x02,
        }
    }
}

/// Everything of a leaf that its signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafBody {
    pub hash_form: HashForm,
    pub content_hash: Hash,
    /// The issuing certificate, by object hash.
    pub issuer: Hash,
    /// Who vouches for the file. The chain bounds it.
    pub name: String,
    pub warrants: Vec<Warrant>,
}

impl LeafBody {
    /// The bytes an issuer signs.
    pub fn to_be_signed(&self) -> Result<Vec<u8>, Malformed> {
        if !valid_leaf_name(&self.name) {
            return Err(Malformed::BadName);
        }
        let mut out = Vec::new();
        put_header(&mut out, Kind::Leaf);
        out.push(self.hash_form.byte());
        out.extend_from_slice(&self.content_hash);
        out.extend_from_slice(&self.issuer);
        put_short_field(&mut out, self.name.as_bytes()).map_err(|_| Malformed::BadName)?;
        warrant::encode_all(&self.warrants, &mut out)?;
        Ok(out)
    }
}

/// A leaf: a signed statement that a file has a given content hash (§7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub body: LeafBody,
    signature: Vec<u8>,
    bytes: Vec<u8>,
}

impl Leaf {
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut reader = Reader::new(bytes);
        expect_header(&mut reader, Kind::Leaf)?;
        let hash_form = HashForm::from_byte(reader.u8()?)?;
        let content_hash = reader.hash()?;
        let issuer = reader.hash()?;
        let name = core::str::from_utf8(reader.short_field()?).map_err(|_| Malformed::BadName)?;
        if !valid_leaf_name(name) {
            return Err(Malformed::BadName);
        }
        let warrants = warrant::decode_all(&mut reader)?;
        let signature = read_signature(&mut reader)?;
        Ok(Self {
            body: LeafBody {
                hash_form,
                content_hash,
                issuer,
                name: name.into(),
                warrants,
            },
            signature,
            bytes: bytes.to_vec(),
        })
    }

    /// The leaf `body` describes, signed with `signature`.
    pub fn from_signed(body: &LeafBody, signature: &[u8]) -> Result<Self, Malformed> {
        let mut bytes = body.to_be_signed()?;
        bytes.extend_from_slice(signature);
        Self::decode(&bytes)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes the signature covers.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() - self.signature.len()]
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The object hash.
    pub fn hash(&self, crypto: &dyn Crypto) -> Hash {
        crypto.sha512(&[&self.bytes])
    }
}

/// A bundle: a leaf and as much of its chain as its signer included (§7.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub leaf: Leaf,
    /// From the leaf's issuer upward.
    pub certificates: Vec<Certificate>,
}

impl Bundle {
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() > MAX_BUNDLE_LEN {
            return Err(Malformed::TooLarge);
        }
        let mut reader = Reader::new(bytes);
        expect_header(&mut reader, Kind::Bundle)?;
        let count = usize::from(reader.u8()?);
        if count > MAX_BUNDLE_CERTIFICATES {
            return Err(Malformed::TooManyCertificates);
        }
        let leaf = Leaf::decode(reader.long_field()?)?;
        let mut certificates = Vec::with_capacity(count);
        for _ in 0..count {
            certificates.push(Certificate::decode(reader.long_field()?)?);
        }
        reader.finish()?;
        Ok(Self { leaf, certificates })
    }
}

/// The bundle holding `leaf` and `certificates`, which are in order from
/// the leaf's issuer upward.
pub fn encode_bundle(leaf: &[u8], certificates: &[&[u8]]) -> Result<Vec<u8>, Malformed> {
    if certificates.len() > MAX_BUNDLE_CERTIFICATES {
        return Err(Malformed::TooManyCertificates);
    }
    let mut out = Vec::new();
    put_header(&mut out, Kind::Bundle);
    out.push(certificates.len() as u8);
    put_long_field(&mut out, leaf)?;
    for certificate in certificates {
        put_long_field(&mut out, certificate)?;
    }
    if out.len() > MAX_BUNDLE_LEN {
        return Err(Malformed::TooLarge);
    }
    // What is written must be what a verifier would accept.
    Bundle::decode(&out)?;
    Ok(out)
}

/// What a revocation or a distrust entry names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetType {
    Certificate,
    Leaf,
}

impl TargetType {
    fn from_byte(byte: u8) -> Result<Self, Malformed> {
        match byte {
            0x01 => Ok(Self::Certificate),
            0x02 => Ok(Self::Leaf),
            _ => Err(Malformed::UnknownTargetType),
        }
    }

    pub fn byte(self) -> u8 {
        match self {
            Self::Certificate => 0x01,
            Self::Leaf => 0x02,
        }
    }
}

/// Everything of a revocation that its signature covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationBody {
    pub target_type: TargetType,
    /// What is revoked, by object hash.
    pub target: Hash,
    /// A certificate, by object hash, or a root, by key hash.
    pub signer: Hash,
}

impl RevocationBody {
    /// The bytes a signer signs.
    pub fn to_be_signed(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_header(&mut out, Kind::Revocation);
        out.push(self.target_type.byte());
        out.extend_from_slice(&self.target);
        out.extend_from_slice(&self.signer);
        out
    }
}

/// A revocation: an authority withdrawing a certificate or a leaf (§7.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    pub body: RevocationBody,
    signature: Vec<u8>,
    bytes: Vec<u8>,
}

impl Revocation {
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut reader = Reader::new(bytes);
        expect_header(&mut reader, Kind::Revocation)?;
        let target_type = TargetType::from_byte(reader.u8()?)?;
        let target = reader.hash()?;
        let signer = reader.hash()?;
        let signature = read_signature(&mut reader)?;
        Ok(Self {
            body: RevocationBody {
                target_type,
                target,
                signer,
            },
            signature,
            bytes: bytes.to_vec(),
        })
    }

    /// The revocation `body` describes, signed with `signature`.
    pub fn from_signed(body: &RevocationBody, signature: &[u8]) -> Result<Self, Malformed> {
        let mut bytes = body.to_be_signed();
        bytes.extend_from_slice(signature);
        Self::decode(&bytes)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes the signature covers.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() - self.signature.len()]
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The object hash.
    pub fn hash(&self, crypto: &dyn Crypto) -> Hash {
        crypto.sha512(&[&self.bytes])
    }
}

/// A distrust entry: an administrator refusing a certificate or a leaf on
/// one system (§7.13). It is not signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Distrust {
    pub target_type: TargetType,
    /// What is distrusted, by object hash.
    pub target: Hash,
}

impl Distrust {
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut reader = Reader::new(bytes);
        expect_header(&mut reader, Kind::Distrust)?;
        let target_type = TargetType::from_byte(reader.u8()?)?;
        let target = reader.hash()?;
        reader.finish()?;
        Ok(Self {
            target_type,
            target,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_header(&mut out, Kind::Distrust);
        out.push(self.target_type.byte());
        out.extend_from_slice(&self.target);
        out
    }
}
