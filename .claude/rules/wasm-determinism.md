---
paths:
  - "crates/thoughtmark-wasm/**/*.rs"
  - "packages/core/**/*.ts"
---
# WASM / bindings determinism
- `thoughtmark-wasm` is the ONLY crate allowed `unsafe` and `getrandom/js`; never let either leak into core.
- Build the wasm path with `--no-default-features --features alloc` (NOT `std`). The wasm32 CI job asserts
  `getrandom` and `wasm-bindgen` are ABSENT from `thoughtmark-core`'s `cargo tree`.
- The boundary carries only `Uint8Array` / `string` / `bigint` — never structured JS objects (I1). Type `u64` as
  `bigint` in TS, never `number` (I4: no float on the hashed path).
- `wasm-bindgen` crate version MUST equal the `wasm-bindgen` CLI version (pinned `=0.2.125`). `just doctor` asserts it.
- A Rust panic crossing the boundary becomes an uncatchable `RuntimeError` — keep the no-panic wall intact.
- Output must be byte-identical to native Rust for every `spec/vectors/` case (the conformance gate).
