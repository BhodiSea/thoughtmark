<!-- SPDX-License-Identifier: Apache-2.0 -->
# 3. `just` + pnpm scripts for build orchestration; no Turborepo in v1

- Status: accepted
- Date: 2026-06-17

## Context and problem statement

The repo is polyglot (Cargo + pnpm) with one ordering constraint: Cargo build -> wasm build -> TS conformance.
We need a single, legible build-graph oracle that local hooks and CI both run identically.

## Decision outcome

**`just ci` is the whole CI graph**, in order; CI mirrors it step-for-step and `lefthook` pre-push runs it. **No
Turborepo in v1** — its caching/config surface is misconfigurable and buys little for a two-graph repo with one
seam.

## Consequences

- One file (`justfile`) defines the wall; "green locally" and "green in CI" cannot diverge by construction.
- Revisit a task runner only if the graph grows beyond what ordered `just` recipes express clearly.
