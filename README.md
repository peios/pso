# pso

Peios Signed Objects: a certificate chain with warrants that vouches for a
file's bytes. PGSS chapter 7, "Signed Objects", is the specification, and
this repository implements it.

- `pso-core` holds the objects, warrants and verification. It does no I/O
  and needs no standard library, so that a kernel can share it.
- `pso` holds keys, issuing, the trust store's directories, the places a
  file carries its bundle, and the `pso` command.
- `vectors/` holds chains with the result every verifier must reach for
  them. [vectors/README.md](vectors/README.md) describes the format.

## Build and check

```sh
cargo build
cargo test
cargo clippy --all-targets -- -Dwarnings
```

The repository is not yet built with pekit.

## Using the command

Make a root. Its secret key goes in `root.key`, sealed under a passphrase
the command asks for twice, and its public key in `root.key.pub`. Only the
key file's owner can read it:

```sh
pso root --out root.key
```

Every key `pso` makes is sealed unless you give `--no-passphrase`, which
writes it in the clear and is for development and tests. Opening a sealed
key, to sign with it, asks for its passphrase. See
[Passphrases](#passphrases).

Have the root sign a top-level certificate, making a key for it in the
same step. The key goes in `top.key` and `top.key.pub`, and the command
prints the certificate's hash, which is its file name in a trust store:

```sh
pso cert top-level --name "Example Top-Level" \
    --root-key root.key --new-key top.key \
    --warrant Delegate=2 --warrant Name=example.com \
    --warrant Revoke --warrant Repository \
    --out top.cert
```

Without `--root-key`, the new key signs its own certificate. A verifier
reports a chain beneath such a top-level as Unrooted.

Issue a signing certificate beneath the top-level:

```sh
pso cert intermediary --name "Example Signing 1" \
    --new-key signer.key --issuer top.cert --issuer-key top.key \
    --warrant Name=pkgs.example.com --warrant Repository \
    --out signer.cert
```

Where someone else holds the secret key, such as a partner who sends only
their public key, give `--key <file>.pub` in place of `--new-key`. `pso key
new` makes a key without a certificate.

Sign a file. The bundle goes beside it, as `repository.pso`:

```sh
pso sign repository --issuer signer.cert --issuer-key signer.key \
    --name pkgs.example.com --warrant Repository
```

Verify it against a root and the trust store of the system at `/`:

```sh
pso verify repository --bundle repository.pso --root root.key.pub
```

`pso verify` prints the result and succeeds only if it is at least what
`--require` names, which is `rooted` unless told otherwise.

`pso show` prints what any object holds, `pso revoke` and `pso distrust`
withdraw a certificate or a leaf, and `pso store` lists what a system's
trust store enables, or with `--image` writes the store image a kernel
reads at boot. `pso help` describes each.

## Passphrases

A sealed key file is one line, `pso-sealed-key <type> <hex>`, whose blob is
peios-crypto's `PEIOSEAL` v1 format: Argon2id with its parameters recorded
in the file, and AES-256-GCM over the key's type and seed. It is the format
the CA (pki) seals its keys in, so the two share one implementation's
worth of rules, and `vectors/peioseal.vectors` proves they agree.

A passphrase is never given on the command line. Each command takes it
from one of these, for the key it opens and for a key it seals:

| Opening a key | Sealing a new key | Source |
|---|---|---|
| `--passphrase-fd N` | `--new-passphrase-fd N` | Read from an open descriptor |
| `--passphrase-file FILE` | `--new-passphrase-file FILE` | Read from a file's first line |
| Neither | Neither | Asked for on the terminal |

The terminal is used only when standard input is one; otherwise the command
fails and says what to give. A new passphrase needs at least 15
characters, and every passphrase is normalised to Unicode NFKC first, as
pki's are, so the same characters typed differently give the same key.

Seal a plain key file in place, or change a sealed key's passphrase:

```sh
pso key encrypt signer.key
pso key passphrase signer.key
```

Both write the new file beside the old one and rename it over it, so a
failure leaves the old file. Sealing a plain file doesn't scrub the plain
key's bytes from the disk: if it mattered that they were never written,
make the key sealed in the first place.

A plain key file, `pso-secret-key <type> <hex>`, still opens without a
passphrase.

## Warrants on the command line

`Delegate=<depth>` and `Name=<name>[,<name>...]` are written as shown.
`Revoke`, `Repository` and `TrustStore` are written as their name alone.

Any other warrant is written `[strict+][must+]<type>:<name>[=<value>]`.
The type is `set`, `namespace` or `limit`. `strict` means a child's value
must be narrower than its parent's, and `must` marks the warrant Must
Understand:

```sh
--warrant set:com.example.Scanner=fast,deep
--warrant strict+limit:com.example.Depth=3
```

## Where a bundle goes

`pso sign --place` chooses among three places:

- `detached`, the default: a file beside the signed one, with `.pso` added.
- `attribute`: the `security.pso` extended attribute, which needs the
  privilege to set one.
- `section`: the `.pso` section of an ELF object. The section must exist
  already, at the bundle's exact size, because the section headers are
  part of what is signed. `pso sign --size` prints the size to reserve.

## What is not here yet

- The ktrust channel (PSPK chapter 6). The store image of that chapter is
  here: `pso store --image` writes one, and `TrustStore::from_image` loads
  one as a kernel does.
- A store keeper: nothing here writes the trust store or asks for
  approval. `pso::store` only reads it.
- Adding a `.pso` section to an ELF object.
