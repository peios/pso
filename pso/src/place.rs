//! The places a file carries its bundle, and the bytes of the file each
//! covers (§7.9).

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha512};

use pso_core::{HASH_LEN, Hash, HashForm, MAX_BUNDLE_LEN};

/// The ELF section a bundle is carried in.
pub const SECTION: &str = ".pso";
/// The section of the older signature format (PSPK §3.2), whose contents
/// the ELF hash form also zeroes.
const OLDER_SECTION: &str = ".peios.sig";
/// The extended attribute a bundle is carried in.
pub const ATTRIBUTE: &str = "security.pso";
/// What a detached bundle's name adds to its file's.
pub const DETACHED_SUFFIX: &str = ".pso";

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF_HEADER_LEN: usize = 64;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const SECTION_HEADER_LEN: usize = 64;
const SHT_PROGBITS: u32 = 1;
const SHN_UNDEF: u16 = 0;
const HASH_CHUNK_LEN: usize = 64 * 1024;

/// Where in a file a section's contents are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub offset: u64,
    pub len: u64,
    section_type: u32,
}

/// The signature sections of an ELF object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SignatureSections {
    bundle: Option<Section>,
    older: Option<Section>,
}

/// A bundle found for a file, and the hash form its place calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub bundle: Vec<u8>,
    pub hash_form: HashForm,
}

/// What looking for a file's bundle found (§7.9, Lookup order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Search {
    /// The file has no bundle.
    Unsigned,
    Found(Found),
    /// The file has a `.pso` section that cannot be used. The extended
    /// attribute is not consulted, and the result is invalid.
    Unusable(String),
}

/// The detached bundle's path for the file at `path`.
pub fn detached_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(DETACHED_SUFFIX);
    PathBuf::from(name)
}

/// Finds the bundle the file at `path` carries, in its `.pso` section or
/// else in its extended attribute.
pub fn find(path: &Path) -> Result<Search> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    if let Some(sections) = signature_sections(&file, len)
        && let Some(section) = sections.bundle
    {
        // Finding the section header commits to it.
        if section.section_type != SHT_PROGBITS {
            return Ok(Search::Unusable(
                "the .pso section is not SHT_PROGBITS".into(),
            ));
        }
        let in_file = section
            .offset
            .checked_add(section.len)
            .is_some_and(|end| end <= len);
        if !in_file || section.len > MAX_BUNDLE_LEN as u64 {
            return Ok(Search::Unusable(
                "the .pso section's range is not usable".into(),
            ));
        }
        let mut bundle = vec![0u8; section.len as usize];
        file.read_exact_at(&mut bundle, section.offset)
            .with_context(|| format!("reading {}", path.display()))?;
        return Ok(Search::Found(Found {
            bundle,
            hash_form: HashForm::Elf,
        }));
    }
    Ok(match attribute(path, ATTRIBUTE)? {
        Some(bundle) => Search::Found(Found {
            bundle,
            hash_form: HashForm::WholeFile,
        }),
        None => Search::Unsigned,
    })
}

/// The value of the extended attribute `name` on the file at `path`, if it
/// has one.
pub fn attribute(path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let c_name = CString::new(name)?;
    let mut value = vec![0u8; MAX_BUNDLE_LEN];
    // SAFETY: both strings are NUL-terminated and outlive the call, and the
    // kernel writes at most `value.len()` bytes into `value`.
    let len = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if len < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            // No such attribute, or a filesystem with none.
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(None),
            _ => Err(error).with_context(|| format!("reading {name} of {}", path.display())),
        };
    }
    value.truncate(len as usize);
    Ok(Some(value))
}

/// Sets the extended attribute `name` on the file at `path`.
pub fn set_attribute(path: &Path, name: &str, value: &[u8]) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let c_name = CString::new(name)?;
    // SAFETY: both strings are NUL-terminated and outlive the call, and the
    // kernel reads exactly `value.len()` bytes from `value`.
    let status = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("setting {name} on {}", path.display()));
    }
    Ok(())
}

/// The content hash of the file at `path` in `hash_form`.
pub fn content_hash(path: &Path, hash_form: HashForm) -> Result<Hash> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    let zeroed: Vec<Section> = match hash_form {
        HashForm::WholeFile => Vec::new(),
        HashForm::Elf => {
            let sections = signature_sections(&file, len).ok_or_else(|| {
                anyhow!("{}: not an ELF object a bundle can go in", path.display())
            })?;
            if sections.bundle.is_none() {
                bail!("{}: has no {SECTION} section", path.display());
            }
            sections.bundle.into_iter().chain(sections.older).collect()
        }
    };
    hash_with_zeroed(&mut file, &zeroed).with_context(|| format!("reading {}", path.display()))
}

/// SHA-512 of `file` with the bytes of each of `zeroed` replaced by zeros.
fn hash_with_zeroed(file: &mut File, zeroed: &[Section]) -> std::io::Result<Hash> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha512::new();
    let mut chunk = vec![0u8; HASH_CHUNK_LEN];
    let mut position = 0u64;
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        for section in zeroed {
            let end = section.offset.saturating_add(section.len);
            let from = section.offset.max(position);
            let to = end.min(position + read as u64);
            if from < to {
                chunk[(from - position) as usize..(to - position) as usize].fill(0);
            }
        }
        hasher.update(&chunk[..read]);
        position += read as u64;
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&hasher.finalize());
    Ok(hash)
}

/// The `.pso` section of the ELF object at `path`, if it has one.
pub fn bundle_section(path: &Path) -> Result<Option<Section>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    Ok(signature_sections(&file, len).and_then(|sections| sections.bundle))
}

/// Writes `bundle` into the `.pso` section of the ELF object at `path`,
/// which must already have one of exactly the bundle's length: the section
/// headers are covered by the hash, so the section cannot be resized after
/// the file is hashed.
pub fn write_section(path: &Path, bundle: &[u8]) -> Result<()> {
    let section = bundle_section(path)?
        .ok_or_else(|| anyhow!("{}: has no {SECTION} section", path.display()))?;
    if section.len != bundle.len() as u64 {
        bail!(
            "{}: its {SECTION} section is {} bytes and the bundle is {}",
            path.display(),
            section.len,
            bundle.len()
        );
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.seek(SeekFrom::Start(section.offset))?;
    file.write_all(bundle)
        .with_context(|| format!("writing {}", path.display()))
}

/// The signature sections of the ELF object `file`, of `len` bytes, or
/// `None` if it is not a 64-bit little-endian ELF object whose section
/// headers can be read (§7.9, The ELF section).
fn signature_sections(file: &File, len: u64) -> Option<SignatureSections> {
    let mut header = [0u8; ELF_HEADER_LEN];
    file.read_exact_at(&mut header, 0).ok()?;
    if &header[..4] != ELF_MAGIC || header[4] != ELFCLASS64 || header[5] != ELFDATA2LSB {
        return None;
    }
    let u16_at = |offset: usize| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let table_offset = u64::from_le_bytes(header[0x28..0x30].try_into().ok()?);
    let entry_len = usize::from(u16_at(0x3A));
    let count = usize::from(u16_at(0x3C));
    let names_index = u16_at(0x3E);
    if entry_len != SECTION_HEADER_LEN
        || names_index == SHN_UNDEF
        || usize::from(names_index) >= count
    {
        return None;
    }
    let table_len = (count * SECTION_HEADER_LEN) as u64;
    if table_offset.checked_add(table_len)? > len {
        return None;
    }
    let mut table = vec![0u8; table_len as usize];
    file.read_exact_at(&mut table, table_offset).ok()?;
    let section = |index: usize| {
        let entry = &table[index * SECTION_HEADER_LEN..(index + 1) * SECTION_HEADER_LEN];
        let name = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        let section_type = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        let offset = u64::from_le_bytes(entry[0x18..0x20].try_into().unwrap());
        let len = u64::from_le_bytes(entry[0x20..0x28].try_into().unwrap());
        (
            name,
            Section {
                offset,
                len,
                section_type,
            },
        )
    };
    let (_, names) = section(usize::from(names_index));
    if names.offset.checked_add(names.len)? > len {
        return None;
    }
    let mut name_table = vec![0u8; usize::try_from(names.len).ok()?];
    file.read_exact_at(&mut name_table, names.offset).ok()?;

    // The comparison takes in the terminating NUL, so a longer name with
    // this one as a prefix does not match. The lowest index wins.
    let named = |wanted: &str| {
        (0..count).map(section).find_map(|(name, found)| {
            let start = name as usize;
            let end = start.checked_add(wanted.len())?;
            let matches =
                name_table.get(start..end)? == wanted.as_bytes() && name_table.get(end) == Some(&0);
            matches.then_some(found)
        })
    };
    Some(SignatureSections {
        bundle: named(SECTION),
        older: named(OLDER_SECTION),
    })
}
