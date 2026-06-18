# thoughtmark — agent codebook

> Loaded into every session. This is the determinism/security contract. **CI is authoritative** — hooks and
> this file are advisory; the required-checks ruleset is the wall you cannot route around. Path-scoped rules live
> in [`.claude/rules/`](.claude/rules/) and load when matching files are touched.

## What this is

Tamper-evident provenance library for human–AI reasoning trails.
Rust core (`thoughtmark-core`) → WASM/TS bindings (`@thoughtmark/core`) → Next.js/Supabase reference app.
License: Apache-2.0. This code is authored almost entirely by Claude Code with no human reviewing every line, so
quality rests on deterministic, machine-checkable gates. **Phase 0 is the gate net itself, stood up against stub
crates** (functions that return `Err(NotImplemented)`); product behavior arrives in Phase 1+.

## What the system proves (read `docs/threat-model.md` before touching docs/UI)

- **Proves — integrity-of-record:** a record existed at time T, in lineage L, unaltered since capture; append-only
  consistency; signer identity.
- **Does NOT prove:** validity (the content is true), faithfulness (the logged reasoning reflects real
  computation), split-view resistance without witnesses, or truth-at-capture (the oracle problem).
- **Never let green CI be read as a claim about the _content_ being notarized.** This honesty frame (I7) is
  load-bearing on the type names, field names, and prose.

## Architecture map (arch §3)

- `crates/thoughtmark-core` — THE pure audited primitive. `#![no_std]`+`alloc`, `#![forbid(unsafe_code)]`, no I/O,
  no clock, no RNG-source, no network. Tier 0 (canon/hash/CID) + Tier 1 (Merkle/DSSE) math.
- `crates/thoughtmark-schema` — serde wire types. `#![no_std]`+`alloc`. The `no_std` island is exactly
  `{ core, schema }` — precisely the audited, byte-identical surface.
- `crates/thoughtmark-wasm` — cdylib+rlib wasm-bindgen shim. **The ONLY crate allowed `unsafe` / `getrandom-js`.**
- `crates/thoughtmark-cli` (`tm`), `-schemagen` (build-only), `-testkit` (dev-only; hosts the conformance test).
- `packages/core` = `@thoughtmark/core` — wraps the wasm-pack `--target web` artifact + a hand-written TS facade.
  The two build graphs (Cargo + pnpm) touch at **exactly one seam**: `thoughtmark-wasm` cdylib → `packages/core`.
- `spec/` — the language-neutral oracle. `spec/SPEC.md` (BCP-14, stable req IDs) + `spec/vectors/` (the corpus).
- Dependency arrows point **INWARD to core**; no plugin is ever a dependency of core (I8, CI-enforced).

## Invariants (NEVER violate) — arch §2.1, I1–I8

- **I1 Byte-identity.** Outputs MUST be byte-identical across the Rust core, WASM, and TS. The `spec/vectors/`
  corpus is the oracle. The cross-language conformance job (the single most load-bearing control) asserts it.
- **I2 JCS-before-hash.** ALWAYS canonicalize JSON via RFC 8785 JCS before hashing — no bare `H(json)` — through
  the single in-house choke point `thoughtmark_core::canon::jcs` (ADR-0001 **amended**: `serde_json_canonicalizer`
  is `std`-only, so it is a dev-only differential oracle, not the implementation). `serde_jcs` is **BANNED**
  (abandoned, RFC 8785 divergences — ADR-0001).
- **I3 No ambient nondeterminism** in core logic: no `SystemTime::now`, `Instant::now`, `thread_rng`,
  `rand::random`. Time enters as `Clock::now() -> UnixMillis`; randomness as injected `Rng`/`Csprng` traits.
- **I4 No floating point** anywhere on the canonicalization / hashing / CID / Merkle path (WASM has NaN-bit and
  signed-zero nondeterminism). `f32`/`f64` are `disallowed-types` there; oversized ints are decimal strings.
- **I5 Salted hashes only.** Store only salted commitments; NEVER store sensitive content or put content on any
  chain. On-ledger types structurally cannot carry a plaintext body.
- **I6 Audited crypto only.** Ed25519 via `ed25519-dalek` 2.x with **`verify_strict` always** (the only sanctioned
  verification path; bare `verify` is banned). Hashing via `blake3` + `sha2`. Never hand-roll crypto.
- **I7 Integrity, not validity, not faithfulness** (see threat model above).
- **I8 Pure, layered, audited core.** Enforced by `forbid(unsafe_code)` + the dependency-direction `cargo
metadata` check.

## The no-panic wall (arch §2.3)

A Rust panic crossing the WASM boundary becomes an uncatchable `RuntimeError`. So core denies:
`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `unreachable`, `todo`,
`float_arithmetic`, `string_slice`. Each "impossible" case returns `Error::Internal(&'static str)`, never panics.

## Never do

- Mutate, `.skip()`, or `#[ignore]` a test to make it pass. Do not weaken a `spec/vectors/` expected value to make
  a diff go away — changing an expected hash is a **breaking spec change** (MAJOR corpus release + CHANGELOG).
- Weaken a lint, a `deny.toml` rule, a hook, or a CI gate. Edits to `.claude/**`, `.github/**`, `deny.toml`,
  `rust-toolchain.toml` require a human (they are `deny`-listed in `.claude/settings.json`).
- Add a dependency without `cargo deny check` (and a `cargo vet` entry). Add a networking crate, `getrandom`,
  `wasm-bindgen`, `tokio`, or `reqwest` to `thoughtmark-core`'s closure — the dep-direction check will fail.
- Introduce a float, `SystemTime::now`, or `thread_rng` on the canon/hash/CID/merkle path.
- Use bare Ed25519 `verify` (use `verify_strict`); add a SECOND canonicalizer (the in-house `canon::jcs` is the
  one choke point — ADR-0001 amended); use `serde_jcs`.
- Push to a protected branch or force-push.

## Build / test / lint (run before every commit)

- `just ci` — the whole CI graph in order (Cargo → wasm build → TS conformance). It is the single build-graph
  oracle (ADR-0003). Pieces: `just doctor` (assert toolchain), `just ci-rust`, `just ci-wasm`, `just ci-ts`,
  `just ci-docs`.
- `just ci` = `fmt --check`, `clippy -D warnings`, `nextest`, **conformance**, `deny`, `audit`, dep-direction +
  wasm32 no-leak assertions, `tsc --noEmit`, `biome check`, wasm-bindgen-test, `publint`/`attw`, `knip`.
- Toolchain is pinned by `rust-toolchain.toml` (1.96.0); `just doctor` asserts the active `cargo` is the rustup
  shim and `wasm-bindgen` CLI == the `=0.2.125` crate pin.

## Definition of Done

A change is done when: it compiles with `-D warnings`; clippy (all/pedantic/cargo + the no-panic wall) is clean;
the cross-language conformance vectors are byte-identical (Rust ⟷ WASM/TS); new behavior has proptest + example
tests **and** a `spec/vectors/` entry; public-API changes pass `cargo-semver-checks`; docs build with no
missing-docs; and `just ci` is green locally. Then — and only then — CI must also be green; CI is the authority.
