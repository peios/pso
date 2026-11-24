# PEIOSEAL vectors

`peioseal.vectors` holds blobs in peios-crypto's `PEIOSEAL` v1 format,
which the CA (pki) and pso both use to seal a key under a passphrase. Each
case was sealed once by one implementation and is opened by the other:

| Case | Sealed by | Opened by |
|---|---|---|
| `peios-crypto-ascii` | peios-crypto | pso, in `pso/tests/sealed.rs` |
| `peios-crypto-nfkc` | peios-crypto | pso, from a passphrase typed in decomposed form |
| `pso-ascii` | pso | peios-crypto, by hand on 2026-11-24 |

Sealing draws a fresh salt and nonce, so a blob can't be regenerated. To add
a case, seal it with one implementation and open it with the other before
committing it.

Each case gives `typed`, the passphrase as entered; `passphrase`, its
Unicode NFKC form in UTF-8, hexadecimal, which is what is sealed under;
`plaintext`, a PSO key file's sealed bytes (the key type byte, then the
32-byte seed); and `blob`. A repository that implements the format can
open every case to prove it agrees.
