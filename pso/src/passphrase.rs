//! Passphrases that protect key files, and where they come from.
//!
//! The rules are pki-keys': the text is normalised to Unicode NFKC, so a
//! passphrase typed on another keyboard or system, which may encode the same
//! characters differently, gives the same key; and a passphrase that seals a
//! key has at least [`MIN_PASSPHRASE_CHARS`] characters once normalised.
//! Keeping both rules the same is what lets a key sealed by one tool open in
//! the other.
//!
//! A passphrase is never taken from the command line or the environment,
//! where other processes and shell histories can see it.

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The fewest characters a new passphrase may have: the minimum NIST SP
/// 800-63B-4 sets for a password used on its own, and pki-keys'.
///
/// A sealed key file can be attacked offline by whoever copies it, so
/// nothing limits their guesses. Argon2id makes each guess costly; length is
/// what makes guessing hopeless. There are no composition rules.
pub const MIN_PASSPHRASE_CHARS: usize = 15;

/// The most a passphrase source is read, so that a misdirected file can't
/// be read whole.
const MAX_PASSPHRASE_BYTES: u64 = 4096;

/// A passphrase for opening a key that exists. No strength rule applies.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(text: &str) -> Self {
        Self(normalise(text))
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A passphrase for sealing a key: at least [`MIN_PASSPHRASE_CHARS`]
/// characters once normalised. Every path that seals a key takes this type,
/// so nothing seals a key under a shorter one.
pub struct NewPassphrase(Passphrase);

impl NewPassphrase {
    pub fn new(text: &str) -> Result<Self> {
        let passphrase = Passphrase::new(text);
        let chars = passphrase.0.chars().count();
        if chars < MIN_PASSPHRASE_CHARS {
            bail!(
                "the passphrase has {chars} characters and needs at least {MIN_PASSPHRASE_CHARS}"
            );
        }
        Ok(Self(passphrase))
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
}

fn normalise(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.nfkc().collect())
}

/// Where a passphrase comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Read from an open file descriptor, which is read once and closed.
    Fd(i32),
    /// Read from a file.
    File(PathBuf),
    /// Asked for on the terminal, if standard input is one. Otherwise the
    /// error names `alternatives`, the other ways to give one.
    Prompt { alternatives: String },
}

impl Source {
    /// The source that `fd` or `file` names, or the terminal if neither.
    /// `alternatives` names the options that give them, for the error when
    /// there is no terminal to ask on.
    pub fn from_options(fd: Option<i32>, file: Option<&Path>, alternatives: &str) -> Self {
        match (fd, file) {
            (Some(fd), _) => Self::Fd(fd),
            (None, Some(file)) => Self::File(file.to_owned()),
            (None, None) => Self::Prompt {
                alternatives: alternatives.to_owned(),
            },
        }
    }

    /// Reads a passphrase for opening the key described as `what`.
    pub fn read(&self, what: &str) -> Result<Passphrase> {
        Ok(Passphrase::new(
            &self.text(&format!("Passphrase for {what}: "))?,
        ))
    }

    /// Reads a passphrase for sealing the key described as `what`. Typed on
    /// the terminal, it is asked for twice.
    pub fn read_new(&self, what: &str) -> Result<NewPassphrase> {
        let text = self.text(&format!("New passphrase for {what}: "))?;
        let passphrase = NewPassphrase::new(&text)?;
        if matches!(self, Self::Prompt { .. }) {
            let again = self.text("Again: ")?;
            if *again != *text {
                bail!("the two passphrases differ");
            }
        }
        Ok(passphrase)
    }

    fn text(&self, prompt: &str) -> Result<Zeroizing<String>> {
        let text = match self {
            Self::Fd(fd) => {
                if *fd < 0 {
                    bail!("--passphrase-fd {fd} is not a file descriptor");
                }
                // SAFETY: the caller named this descriptor on the command
                // line for this purpose, so this process may read it and
                // owns closing it. It is taken once: a `Source` read twice
                // fails with EBADF rather than reading another file.
                let file = unsafe { File::from_raw_fd(*fd) };
                read_limited(file)
                    .with_context(|| format!("reading the passphrase from descriptor {fd}"))?
            }
            Self::File(path) => {
                let file = File::open(path)
                    .with_context(|| format!("reading the passphrase from {}", path.display()))?;
                read_limited(file)
                    .with_context(|| format!("reading the passphrase from {}", path.display()))?
            }
            Self::Prompt { alternatives } => {
                if !io::stdin().is_terminal() {
                    bail!(
                        "a passphrase is needed and standard input is not a terminal; {alternatives}"
                    );
                }
                Zeroizing::new(
                    rpassword::prompt_password(prompt).context("reading the passphrase")?,
                )
            }
        };
        Ok(text)
    }
}

/// The first line of `file`, without its line ending.
fn read_limited(file: File) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PASSPHRASE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PASSPHRASE_BYTES {
        bail!("longer than {MAX_PASSPHRASE_BYTES} bytes, so not a passphrase");
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("not UTF-8"))?;
    let line = text.split(['\n', '\r']).next().unwrap_or_default();
    Ok(Zeroizing::new(line.to_owned()))
}
