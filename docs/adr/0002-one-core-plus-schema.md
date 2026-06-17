<!-- SPDX-License-Identifier: Apache-2.0 -->
# 2. One `thoughtmark-core` crate + a separate `thoughtmark-schema`

- Status: accepted
- Date: 2026-06-17
- Realizes: I8 (pure, layered, audited core)

## Context and problem statement

The audited surface (Tier 0 + Tier 1 math) could be split into `-canon`/`-crypto`/`-merkle` crates, or kept as
one. We want the trusted surface to be auditable as a single unit while keeping the serde wire types free to
evolve.

## Decision outcome

Ship **one `thoughtmark-core`** (canon, hash, CID, Merkle, DSSE, determinism, error model) plus a **separate
`thoughtmark-schema`** (wire structs). Both are `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`. Modules inside
core are separated cleanly so a later split is mechanical.

## Consequences

- The `no_std` island is exactly `{ core, schema }` — precisely the byte-identical surface a reviewer must trust.
- No premature crate proliferation; one `cargo deny`/`cargo vet` trust unit for the core.
