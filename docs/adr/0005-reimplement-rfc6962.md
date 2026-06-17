<!-- SPDX-License-Identifier: Apache-2.0 -->
# 5. Reimplement RFC 6962 Merkle math in core; external CT crates as differential oracles only

- Status: accepted
- Date: 2026-06-17
- Realizes: I1 (byte-identity), I6 (audited crypto), I8

## Context and problem statement

Tier-1 transparency-log proofs (RFC 6962) must be byte-identical in WASM, run under `#![forbid(unsafe_code)]`, and
be offline-deterministic. An external CT crate risks a domain-separation/leaf-encoding mismatch and may breach
`forbid(unsafe)` or pull non-deterministic dependencies.

## Decision outcome

**Reimplement RFC 6962 leaf/node hashing and proof math inside `thoughtmark-core::merkle`** (~300 LOC; it *is* the
spec). Use `transparency-dev/merkle`, `ct-merkle`, and `tlog_tiles` as **differential oracles** in tests only.

## Consequences

- The proof math is part of the audited, byte-identical surface and the conformance corpus.
- A small, well-tested reimplementation we fully control; external crates validate it without shipping in it.
