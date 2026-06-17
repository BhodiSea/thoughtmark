<!-- SPDX-License-Identifier: Apache-2.0 -->
# 1. JCS canonicalization crate: `serde_json_canonicalizer`; `serde_jcs` is banned

- Status: accepted
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
