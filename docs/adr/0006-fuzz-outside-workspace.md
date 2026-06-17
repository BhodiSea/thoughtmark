<!-- SPDX-License-Identifier: Apache-2.0 -->
# 6. `fuzz/` lives outside the Cargo workspace

- Status: accepted
- Date: 2026-06-17

## Context and problem statement

`cargo-fuzz` pins a dated nightly toolchain. If `fuzz/` were a workspace member, building/testing the workspace
would drag the whole repo off the pinned **1.96.0 stable** toolchain.

## Decision outcome

`fuzz/` is a **standalone Cargo project** (`publish = false`, its own empty `[workspace]`, and `exclude = ["fuzz"]`
in the root workspace). It runs in a **dedicated nightly CI job**, never on the stable `just ci` green path.

## Consequences

- The workspace stays on 1.96.0 stable; fuzzing uses nightly in isolation.
- Fuzz targets (`jcs`, `cid`, …) are wired now and activate per-parser as that parser lands (Phase 1+).
