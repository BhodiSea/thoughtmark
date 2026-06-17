<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to thoughtmark

This codebase is authored almost entirely by Claude Code. **CI is authoritative**: a change merges only when the
required checks are green. Hooks and local checks are advisory mirrors of CI — they cannot be the only gate.

## Before you start

- Read `CLAUDE.md` (the codebook), `docs/threat-model.md` (integrity, not validity), and the relevant
  `.claude/rules/*.md`.
- Honor the invariants I1–I8. In particular: canonicalize (JCS) before hashing; no ambient nondeterminism; no
  floats on the canon/hash/CID/merkle path; salted hashes only; audited crypto only (`verify_strict`).

## The loop

1. `just doctor` — confirm the pinned toolchain (Rust 1.96.0 via the rustup shim; `wasm-bindgen` 0.2.125).
2. Make the change. New behavior needs a `spec/vectors/` entry, a proptest property where one applies, and an
   example/snapshot test.
3. `just ci` — the whole wall: fmt/clippy `-D warnings`/nextest/**conformance**/deny/audit/tsc/biome/wasm
   tests/publint/attw/knip + the dependency-direction and no-leak assertions.
4. Open a PR; fill the Definition of Done checklist.

## Normative changes (spec / wire format / corpus)

- A change to `spec/SPEC.md` requirements, the wire format, or any **expected value** in `spec/vectors/` is a
  normative change. Changing an expected hash is a **breaking** corpus change: bump `spec/vectors/VERSION`
  (MAJOR) and append to its `CHANGELOG.md`.
- Guardrail files (`.claude/**`, `.github/**`, `deny.toml`, `rust-toolchain.toml`, `clippy.toml`) require a human
  reviewer (CODEOWNERS); the AI author may not weaken them.

## Commits & history

- Conventional Commits. Signed commits and linear history are enforced by the repository ruleset (see
  `BOOTSTRAP.md`). Never force-push a protected branch.
