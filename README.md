<!-- SPDX-License-Identifier: Apache-2.0 -->
# thoughtmark

Tamper-evident provenance for human–AI reasoning trails. A pure, audited Rust core (`thoughtmark-core`,
`#![no_std]` + `forbid(unsafe)`) compiles to WASM/TypeScript bindings (`@thoughtmark/core`) that are
**byte-identical** to the native core, validated by a versioned conformance corpus.

> **Integrity, not validity.** thoughtmark proves a record *existed at a time, in a lineage, unaltered since
> capture* — append-only consistency and signer identity. It does **not** prove the content is true, that a logged
> reasoning trail is faithful, or split-view resistance without witnesses. See [docs/threat-model.md](docs/threat-model.md).
> A green check is never a claim about the content being notarized.

## Status — Phase 0 (Foundations & Quality Spine)

This is the **pre-implementation quality contract**: the entire gate net, stood up against **stub crates** (every
operation returns the canonical `NOT_IMPLEMENTED` envelope) so the first implementation PR already runs inside the
wall. The single most load-bearing control — the cross-language conformance gate — runs from the first commit,
asserting Rust ⟷ WASM/TS byte-equality even on "not implemented". No product behavior yet; Tier-0 logic
(canon/hash/CID) lands in Phase 1.

## Layout

| Path | What |
|---|---|
| `crates/thoughtmark-core` | The pure audited primitive (`no_std`+`alloc`, `forbid(unsafe)`). |
| `crates/thoughtmark-schema` | Reasoning-trail wire types (separate per ADR-0002). |
| `crates/thoughtmark-wasm` | The WASM/TS seam — the only crate allowed `unsafe`/`getrandom-js`. |
| `crates/thoughtmark-{cli,schemagen,testkit}` | `tm` CLI, codegen, the conformance harness host. |
| `packages/core` | `@thoughtmark/core` — TS facade over the wasm-pack `--target web` artifact. |
| `spec/` | `SPEC.md` (BCP-14 requirements) + `spec/vectors/` (the executable conformance corpus). |
| `docs/` | ADRs, threat model, mdBook guide. |
| `fuzz/` | Standalone cargo-fuzz project (outside the workspace, ADR-0006). |

## Quickstart

```sh
. "$HOME/.cargo/env"   # rustup shim must precede Homebrew cargo (R1)
just doctor            # assert the pinned toolchain (Rust 1.96.0; wasm-bindgen 0.2.125)
just ci                # the whole wall: fmt/clippy/nextest/CONFORMANCE/deny/audit/tsc/biome/wasm/publint/attw/knip
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [BOOTSTRAP.md](BOOTSTRAP.md) (the
server-side governance runbook). Licensed under [Apache-2.0](LICENSE).
