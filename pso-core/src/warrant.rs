//! Warrants: named powers written into a certificate or requested by a leaf,
//! and the rule that a child never holds more than its parent (§7.5).

use alloc::string::String;
use alloc::vec::Vec;

use crate::object::Malformed;
use crate::wire::{Reader, put_long_field, put_short_field};

/// How many certificates can stand between the holder and a leaf.
pub const DELEGATE: &str = "Delegate";
/// The names the holder's leaves can be issued under.
pub const NAME: &str = "Name";
/// The holder can revoke itself and what is beneath it.
pub const REVOKE: &str = "Revoke";

const ALLOW_EQUAL: u8 = 0x80;
const TYPE_MASK: u8 = 0x70;
const TYPE_SHIFT: u8 = 4;
const MUST_UNDERSTAND: u8 = 0x08;
const RESERVED: u8 = 0x07;

/// The separator between the elements of a Set or Namespace value.
const SEPARATOR: u8 = 0x00;
/// The name every other name is within.
const UNIVERSAL: &str = ".";
const LIMIT_LEN: usize = 8;

/// The form of a warrant's value, and how one value is narrower than another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WarrantType {
    /// Zero or more elements. A child's are a subset of its parent's.
    Set,
    /// One or more names. Each of a child's is within one of its parent's.
    Namespace,
    /// One number. A child's is no greater than its parent's.
    Limit,
}

impl WarrantType {
    fn bits(self) -> u8 {
        let value = match self {
            Self::Set => 0,
            Self::Namespace => 1,
            Self::Limit => 2,
        };
        value << TYPE_SHIFT
    }
}

/// Why a child's warrant does not narrow against its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NarrowError {
    Added,
    FlagsDiffer,
    Wider,
    NotNarrower,
}

/// One warrant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warrant {
    name: String,
    flags: u8,
    value: Vec<u8>,
}

impl Warrant {
    /// A Set warrant holding `elements`, which is a plain flag if there are
    /// none.
    pub fn set(name: &str, elements: &[&str], allow_equal: bool) -> Result<Self, Malformed> {
        Self::build(name, WarrantType::Set, allow_equal, join(elements))
    }

    /// A Namespace warrant holding `names`.
    pub fn namespace(name: &str, names: &[&str], allow_equal: bool) -> Result<Self, Malformed> {
        Self::build(name, WarrantType::Namespace, allow_equal, join(names))
    }

    /// A Limit warrant holding `limit`.
    pub fn limit(name: &str, limit: u64, allow_equal: bool) -> Result<Self, Malformed> {
        Self::build(
            name,
            WarrantType::Limit,
            allow_equal,
            limit.to_le_bytes().to_vec(),
        )
    }

    /// `Delegate`: `depth` certificates can stand between the holder and a
    /// leaf.
    pub fn delegate(depth: u64) -> Self {
        Self::limit(DELEGATE, depth, false).expect("Delegate is a valid warrant")
    }

    /// `Name`: the holder's leaves can be issued under `names`.
    pub fn name_warrant(names: &[&str]) -> Result<Self, Malformed> {
        Self::namespace(NAME, names, true)
    }

    /// `Revoke`: the holder can revoke itself and what is beneath it.
    pub fn revoke() -> Self {
        Self::set(REVOKE, &[], true).expect("Revoke is a valid warrant")
    }

    /// The same warrant, which a verifier that does not recognize its name
    /// must refuse.
    pub fn must_understand(mut self) -> Self {
        self.flags |= MUST_UNDERSTAND;
        self
    }

    fn build(
        name: &str,
        warrant_type: WarrantType,
        allow_equal: bool,
        value: Vec<u8>,
    ) -> Result<Self, Malformed> {
        let flags = warrant_type.bits() | if allow_equal { ALLOW_EQUAL } else { 0 };
        let warrant = Self {
            name: name.into(),
            flags,
            value,
        };
        warrant.validate()?;
        Ok(warrant)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn warrant_type(&self) -> WarrantType {
        match (self.flags & TYPE_MASK) >> TYPE_SHIFT {
            0 => WarrantType::Set,
            1 => WarrantType::Namespace,
            // `validate` admits no other type.
            _ => WarrantType::Limit,
        }
    }

    /// Whether a child's value can equal this one.
    pub fn allows_equal(&self) -> bool {
        self.flags & ALLOW_EQUAL != 0
    }

    /// Whether a verifier that does not recognize the name must refuse it.
    pub fn is_must_understand(&self) -> bool {
        self.flags & MUST_UNDERSTAND != 0
    }

    /// The elements of a Set or Namespace value.
    pub fn elements(&self) -> impl Iterator<Item = &[u8]> {
        let has_elements = self.warrant_type() != WarrantType::Limit && !self.value.is_empty();
        self.value
            .split(|byte| *byte == SEPARATOR)
            .filter(move |_| has_elements)
    }

    /// The number of a Limit value.
    pub fn limit_value(&self) -> Option<u64> {
        if self.warrant_type() != WarrantType::Limit {
            return None;
        }
        Some(u64::from_le_bytes(self.value.as_slice().try_into().ok()?))
    }

    fn validate(&self) -> Result<(), Malformed> {
        let name_ok = !self.name.is_empty()
            && self.name.len() <= usize::from(u8::MAX)
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if !name_ok {
            return Err(Malformed::BadWarrant);
        }
        if self.flags & RESERVED != 0 {
            return Err(Malformed::ReservedSet);
        }
        match (self.flags & TYPE_MASK) >> TYPE_SHIFT {
            0 => validate_elements(&self.value, |element| {
                element.iter().all(|b| (0x20..=0x7E).contains(b))
            }),
            1 if self.value.is_empty() => Err(Malformed::BadWarrant),
            1 => validate_elements(&self.value, is_namespace_name),
            2 if self.value.len() == LIMIT_LEN => Ok(()),
            _ => Err(Malformed::BadWarrant),
        }
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let name = reader.short_field()?;
        let name = core::str::from_utf8(name).map_err(|_| Malformed::BadWarrant)?;
        let flags = reader.u8()?;
        let value = reader.long_field()?.to_vec();
        let warrant = Self {
            name: name.into(),
            flags,
            value,
        };
        warrant.validate()?;
        Ok(warrant)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Malformed> {
        put_short_field(out, self.name.as_bytes())?;
        out.push(self.flags);
        put_long_field(out, &self.value)
    }

    /// Whether this warrant, held by a child, is no wider than `parent`'s
    /// and, where the parent does not allow an equal value, differs from it.
    fn narrows(&self, parent: &Self) -> Result<(), NarrowError> {
        if self.flags != parent.flags {
            return Err(NarrowError::FlagsDiffer);
        }
        let (no_wider, equal) = match self.warrant_type() {
            WarrantType::Set => {
                let no_wider = self.elements().all(|e| parent.elements().any(|p| p == e));
                (
                    no_wider,
                    no_wider && parent.elements().all(|p| self.elements().any(|e| e == p)),
                )
            }
            WarrantType::Namespace => {
                let no_wider = self
                    .elements()
                    .all(|e| parent.elements().any(|p| bytes_within(e, p)));
                (
                    no_wider,
                    no_wider && parent.elements().all(|p| self.elements().any(|e| e == p)),
                )
            }
            WarrantType::Limit => (
                self.limit_value() <= parent.limit_value(),
                self.limit_value() == parent.limit_value(),
            ),
        };
        if !no_wider {
            return Err(NarrowError::Wider);
        }
        if equal && !parent.allows_equal() {
            return Err(NarrowError::NotNarrower);
        }
        Ok(())
    }
}

fn join(elements: &[&str]) -> Vec<u8> {
    elements.join("\0").into_bytes()
}

/// Checks the elements of a Set or Namespace value: none empty, none twice,
/// and each one that `valid` accepts. An empty value has no elements.
fn validate_elements(value: &[u8], valid: impl Fn(&[u8]) -> bool) -> Result<(), Malformed> {
    if value.is_empty() {
        return Ok(());
    }
    let elements: Vec<&[u8]> = value.split(|byte| *byte == SEPARATOR).collect();
    for (index, element) in elements.iter().enumerate() {
        if element.is_empty() || !valid(element) || elements[..index].contains(element) {
            return Err(Malformed::BadWarrant);
        }
    }
    Ok(())
}

/// Whether `name` has the form of a Namespace name: labels of lowercase
/// letters, digits and `-`, joined by `.`, or `.` alone.
fn is_namespace_name(name: &[u8]) -> bool {
    if name == UNIVERSAL.as_bytes() {
        return true;
    }
    name.split(|byte| *byte == b'.').all(|label| {
        !label.is_empty()
            && label
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    })
}

fn bytes_within(name: &[u8], parent: &[u8]) -> bool {
    if parent == UNIVERSAL.as_bytes() || name == parent {
        return true;
    }
    // The `.` before the suffix is what stops `evilexample.com` being
    // within `example.com`.
    name.len() > parent.len()
        && name.ends_with(parent)
        && name[name.len() - parent.len() - 1] == b'.'
}

/// Whether `name` is within `parent`: equal to it, or ending with `.` and
/// then it. Every name is within `.`.
pub fn name_is_within(name: &str, parent: &str) -> bool {
    bytes_within(name.as_bytes(), parent.as_bytes())
}

/// Whether `name` can be a leaf's name: a Namespace name other than `.`.
pub fn valid_leaf_name(name: &str) -> bool {
    name != UNIVERSAL && name.len() <= usize::from(u8::MAX) && is_namespace_name(name.as_bytes())
}

/// The warrant named `name` among `warrants`.
pub(crate) fn find<'a>(warrants: &'a [Warrant], name: &str) -> Option<&'a Warrant> {
    warrants.iter().find(|warrant| warrant.name == name)
}

/// Reads a count and that many warrants, which must be in ascending order
/// of name with none twice.
pub(crate) fn decode_all(reader: &mut Reader<'_>) -> Result<Vec<Warrant>, Malformed> {
    let count = reader.u8()?;
    let mut warrants: Vec<Warrant> = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let warrant = Warrant::decode(reader)?;
        if warrants
            .last()
            .is_some_and(|last| last.name.as_bytes() >= warrant.name.as_bytes())
        {
            return Err(Malformed::WarrantOrder);
        }
        warrants.push(warrant);
    }
    Ok(warrants)
}

/// Writes `warrants` in ascending order of name. Two of one name is an
/// error.
pub(crate) fn encode_all(warrants: &[Warrant], out: &mut Vec<u8>) -> Result<(), Malformed> {
    let mut sorted: Vec<&Warrant> = warrants.iter().collect();
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    if sorted.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(Malformed::WarrantOrder);
    }
    out.push(u8::try_from(sorted.len()).map_err(|_| Malformed::TooManyWarrants)?);
    for warrant in sorted {
        warrant.validate()?;
        warrant.encode(out)?;
    }
    Ok(())
}

/// Checks every warrant of `child` against `parent` (§7.5, Narrowing), and
/// says which warrant failed and how.
pub(crate) fn narrow_all<'a>(
    child: &'a [Warrant],
    parent: &[Warrant],
) -> Result<(), (&'a str, NarrowError)> {
    for warrant in child {
        let held =
            find(parent, &warrant.name).ok_or((warrant.name.as_str(), NarrowError::Added))?;
        warrant
            .narrows(held)
            .map_err(|error| (warrant.name.as_str(), error))?;
    }
    Ok(())
}
