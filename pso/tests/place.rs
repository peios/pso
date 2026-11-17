//! Where a file carries its bundle, and which of its bytes the content
//! hash covers (§7.9).

use std::fs;

use pso::core::{Crypto, HashForm, RustCrypto};
use pso::place::{self, Search};

const SECTION_HEADER_LEN: usize = 64;

/// A minimal 64-bit little-endian ELF object: `body`, then one section of
/// zeros for each of `sections`, then the section-name table, then the
/// section header table.
fn elf(body: &[u8], sections: &[(&str, usize)]) -> Vec<u8> {
    const HEADER_LEN: usize = 64;
    let mut names = vec![0u8];
    let mut name_offsets = Vec::new();
    for (name, _) in sections.iter().copied().chain([(".shstrtab", 0)]) {
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let mut file = vec![0u8; HEADER_LEN];
    file.extend_from_slice(body);
    let mut headers = vec![[0u8; SECTION_HEADER_LEN]];
    let header = |name: u32, kind: u32, offset: usize, len: usize| {
        let mut entry = [0u8; SECTION_HEADER_LEN];
        entry[0..4].copy_from_slice(&name.to_le_bytes());
        entry[4..8].copy_from_slice(&kind.to_le_bytes());
        entry[0x18..0x20].copy_from_slice(&(offset as u64).to_le_bytes());
        entry[0x20..0x28].copy_from_slice(&(len as u64).to_le_bytes());
        entry
    };
    for (index, (_, len)) in sections.iter().enumerate() {
        headers.push(header(name_offsets[index], 1, file.len(), *len));
        file.extend(std::iter::repeat_n(0u8, *len));
    }
    headers.push(header(
        name_offsets[sections.len()],
        3,
        file.len(),
        names.len(),
    ));
    file.extend_from_slice(&names);
    let table_offset = file.len() as u64;
    for entry in &headers {
        file.extend_from_slice(entry);
    }
    file[..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[0x28..0x30].copy_from_slice(&table_offset.to_le_bytes());
    file[0x3A..0x3C].copy_from_slice(&(SECTION_HEADER_LEN as u16).to_le_bytes());
    file[0x3C..0x3E].copy_from_slice(&(headers.len() as u16).to_le_bytes());
    file[0x3E..0x40].copy_from_slice(&((headers.len() - 1) as u16).to_le_bytes());
    file
}

#[test]
fn bundle_is_found_in_the_pso_section() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program");
    fs::write(&path, elf(b"code", &[(".pso", 40)])).unwrap();
    place::write_section(&path, &[7u8; 40]).unwrap();
    assert_eq!(
        place::find(&path).unwrap(),
        Search::Found(place::Found {
            bundle: vec![7u8; 40],
            hash_form: HashForm::Elf
        })
    );
}

#[test]
fn a_longer_section_name_is_not_the_pso_section() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program");
    fs::write(&path, elf(b"code", &[(".psox", 40)])).unwrap();
    assert_eq!(place::bundle_section(&path).unwrap(), None);
    assert_eq!(place::find(&path).unwrap(), Search::Unsigned);
}

#[test]
fn a_file_that_is_not_elf_has_no_section() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("firmware.bin");
    fs::write(&path, b"not an object").unwrap();
    assert_eq!(place::find(&path).unwrap(), Search::Unsigned);
}

#[test]
fn elf_hash_zeroes_both_signature_sections_and_nothing_else() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program");
    let empty = elf(b"code", &[(".pso", 40), (".peios.sig", 16)]);
    fs::write(&path, &empty).unwrap();
    let before = place::content_hash(&path, HashForm::Elf).unwrap();
    assert_eq!(
        before,
        RustCrypto.sha512(&[&empty]),
        "zeroed sections hash as the zeros they hold"
    );

    // Filling either signature section leaves the ELF hash as it was, and
    // changes the whole-file hash.
    place::write_section(&path, &[9u8; 40]).unwrap();
    let mut filled = fs::read(&path).unwrap();
    let older =
        filled.len() - 4 * SECTION_HEADER_LEN - ".pso\0.peios.sig\0.shstrtab\0".len() - 1 - 16;
    filled[older..older + 16].fill(5);
    fs::write(&path, &filled).unwrap();
    assert_eq!(place::content_hash(&path, HashForm::Elf).unwrap(), before);
    assert_ne!(
        place::content_hash(&path, HashForm::WholeFile).unwrap(),
        before
    );

    // Any other byte is covered.
    filled[64] ^= 1;
    fs::write(&path, &filled).unwrap();
    assert_ne!(place::content_hash(&path, HashForm::Elf).unwrap(), before);
}

#[test]
fn a_bundle_of_another_length_is_not_written() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program");
    fs::write(&path, elf(b"code", &[(".pso", 40)])).unwrap();
    assert!(place::write_section(&path, &[7u8; 41]).is_err());
}

#[test]
fn detached_bundle_is_beside_its_file() {
    assert_eq!(
        place::detached_path("/srv/repo/repository".as_ref()),
        std::path::PathBuf::from("/srv/repo/repository.pso")
    );
}
