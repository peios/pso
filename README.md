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

Make a root. Its secret key goes in `root.key`, which only its owner can
read, and its public key in `root.key.pub`:

```sh
pso root --out root.key
```

Make a key for a top-level and have the root sign a certificate for it.
The command prints the certificate's hash, which is its file name in a
trust store:

```sh
pso key new --out top.key
pso cert top-level --name "Example Top-Level" \
    --root-key root.key --key top.key.pub \
    --warrant Delegate=2 --warrant Name=example.com \
    --warrant Revoke --warrant Repository \
    --out top.cert
```

A top-level can sign itself instead, with `--self-signed top.key`. A
verifier reports a chain beneath one as Unrooted.

Issue a signing certificate beneath the top-level:

```sh
pso key new --out signer.key
pso cert intermediary --name "Example Signing 1" \
    --key signer.key.pub --issuer top.cert --issuer-key top.key \
    --warrant Name=pkgs.example.com --warrant Repository \
    --out signer.cert
```

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
