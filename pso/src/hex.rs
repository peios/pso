//! Lowercase hexadecimal, the form a hash takes as a file name (§7.4).

use anyhow::{Result, bail};

use pso_core::{HASH_LEN, Hash};

pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0F)] as char);
    }
    out
}

/// The bytes `text` gives, which must be lowercase hexadecimal of even
/// length.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    fn digit(character: u8) -> Result<u8> {
        match character {
            b'0'..=b'9' => Ok(character - b'0'),
            b'a'..=b'f' => Ok(character - b'a' + 10),
            _ => bail!("not lowercase hexadecimal"),
        }
    }
    if !text.len().is_multiple_of(2) {
        bail!("hexadecimal of odd length");
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| Ok(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// The hash `text` names, as a file in the trust store is named.
pub fn decode_hash(text: &str) -> Result<Hash> {
    let bytes = decode(text)?;
    if bytes.len() != HASH_LEN {
        bail!("a hash is {} hexadecimal characters", HASH_LEN * 2);
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
