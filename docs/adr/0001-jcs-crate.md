<!-- SPDX-License-Identifier: Apache-2.0 -->
# 1. JCS canonicalization crate: `serde_json_canonicalizer`; `serde_jcs` is banned

- Status: accepted; **amended in Phase 1** (see Amendment below)
- Date: 2026-06-17
- Deciders: thoughtmark maintainers
- Realizes: I2 (JCS-before-hash, single choke point)

## Context and problem statement

Every hash in this system is taken over RFC 8785 (JCS) canonical bytes (I2). For a byte-identical-hash library the
canonicalizer choice **is** a wire-format/spec decision: a single divergence from RFC 8785 silently changes every
downstream hash, CID, Merkle root, and signature, and breaks cross-language byte-identity (I1). It must be recorded
and justified, not left implicit.

## Considered options

- **`serde_json_canonicalizer`** — maintained, tracks RFC 8785.
- **`serde_jcs`** — abandoned, with known RFC 8785 divergences.
- **Hand-rolled JCS** — maximal control, maximal risk; re-implements a subtle spec we would then have to test to
  death.

## Decision outcome

Use **`serde_json_canonicalizer`** as the single canonicalization choke point (`thoughtmark_core::canon`). A clippy
`disallowed-methods` lint bans `serde_json::to_vec`/`to_string` on hashed data so no bypass of the choke point can
land. **`serde_jcs` is BANNED**; it must never appear in `Cargo.toml` or the lock.

## Consequences

- The canonicalizer is part of the conformance contract; bumping it requires re-running the full `spec/vectors/`
  corpus and is treated as potentially breaking.
- Phase 0 stubs do not yet call the crate (the `NOT_IMPLEMENTED` envelope is hand-encoded); the dependency is
  pinned in `[workspace.dependencies]` and wired in Phase 1. Its `no_std`/`alloc` support is verified before it
  enters the `#![no_std]` core (R5) — if unavailable, the canonicalization seam moves to an `alloc` boundary,
  recorded in a follow-up ADR.

## Amendment (Phase 1) — `serde_json_canonicalizer` is std-only; canonicalize in-house, crate as oracle

The Phase-0 verification (above) came back negative. `serde_json_canonicalizer 0.3.2` `use std::io;` and routes
every entry point through `to_writer<W: io::Write>`; `serde_json`'s own streaming `Serializer` is likewise
`std`-gated. So the crate **cannot compile** in the core's wasm build
(`cargo build -p thoughtmark-core --target wasm32-unknown-unknown --no-default-features --features alloc`). Making
the wasm path go through `std` is impossible (`wasm32-unknown-unknown` has no std, and the no-getrandom closure
forbids it); a feature-split (crate on native, in-house on wasm) would ship **two** production canonicalizers that
must agree, achieving I1 by cross-check rather than by construction.

**Resolution.** Canonicalization is implemented **in-house** in `thoughtmark_core::canon::jcs` — one `alloc`
encoder over `serde_json::Value`, compiled identically on native and wasm, so I1 holds *by construction*. This is
the same pattern ADR-0005 already chose for RFC 6962: reimplement the spec in core, use external crates as
**differential oracles only**. The in-house encoder is auditable because the hard part of RFC 8785 (ECMAScript
float formatting) is **never exercised** — `canon::nofloat::validate_no_float` rejects every float and out-of-range
integer first (I4), leaving the encoder to handle only `null` / `bool` / string-escaping / integer-decimal /
array / UTF-16-sorted-object.

**Oracles (not implementations).** `serde_json_canonicalizer` remains a **dev-dependency of `thoughtmark-core`**
only: a proptest asserts `canon::jcs == serde_json_canonicalizer::to_vec` over 2048 arbitrary float-free values
each run. An **independent pure-TS oracle** (`cyberphone/canonicalize` + `@noble/hashes` + `multiformats`)
reproduces every `spec/vectors/` case in CI. Both guard the UTF-16 key sort — the exact divergence that killed
`serde_jcs`. A disagreement is investigated as a real bug, never reconciled by re-blessing.

**Unchanged.** `serde_jcs` is still BANNED. The single-choke-point rule still holds (nothing else in the workspace
canonicalizes). The clippy `disallowed-methods` ban on `serde_json::to_vec`/`to_string` for hashed data still
applies. `serde_json_canonicalizer` MUST NOT appear in any crate's `[dependencies]` (only `[dev-dependencies]` of
`thoughtmark-core`).
