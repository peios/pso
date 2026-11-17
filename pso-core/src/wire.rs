//! Reading and writing the fixed-order, length-prefixed fields every object
//! is made of (§7.4). Integers are little-endian.

use alloc::vec::Vec;

use crate::object::Malformed;

/// A cursor over an object's bytes. Every read fails as `Malformed` if it
/// would run past the end.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], Malformed> {
        if len > self.remaining() {
            return Err(Malformed::Truncated);
        }
        let taken = &self.bytes[self.position..self.position + len];
        self.position += len;
        Ok(taken)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let rest = &self.bytes[self.position..];
        self.position = self.bytes.len();
        rest
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Malformed> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Malformed> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn hash(&mut self) -> Result<[u8; 64], Malformed> {
        let mut hash = [0u8; 64];
        hash.copy_from_slice(self.take(64)?);
        Ok(hash)
    }

    /// A field with a one-byte length before it.
    pub(crate) fn short_field(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    /// A field with a two-byte length before it.
    pub(crate) fn long_field(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    /// Fails unless every byte has been read.
    pub(crate) fn finish(&self) -> Result<(), Malformed> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Malformed::TrailingBytes)
        }
    }
}

pub(crate) fn put_short_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), Malformed> {
    let len = u8::try_from(field.len()).map_err(|_| Malformed::FieldTooLong)?;
    out.push(len);
    out.extend_from_slice(field);
    Ok(())
}

pub(crate) fn put_long_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), Malformed> {
    let len = u16::try_from(field.len()).map_err(|_| Malformed::FieldTooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
    Ok(())
}
