# Working on pso

pso implements PGSS chapter 7, "Signed Objects". The specification is the
authority: where the code and the chapter disagree, find out which is
wrong before changing either, and change the chapter only with Jack.

- Keep `pso-core` free of I/O and of the standard library. A kernel is
  meant to share it.
- A verifier's behavior is pinned by `vectors/pso.vectors`. A change that
  alters any case's result is a change to the specification.
- Add a case to `pso/tests/vectors.rs` for every rule a verifier applies,
  then regenerate the file as `vectors/README.md` describes.
- Follow PSC's common coding rules and Rust profile. Run `cargo fmt`,
  `cargo clippy --all-targets -- -Dwarnings` and `cargo test`.
