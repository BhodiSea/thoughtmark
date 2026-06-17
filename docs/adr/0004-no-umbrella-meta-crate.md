<!-- SPDX-License-Identifier: Apache-2.0 -->
# 4. No umbrella meta-crate; explicit per-plugin dependencies

- Status: accepted
- Date: 2026-06-17
- Realizes: I8; the dependency-direction CI assertion

## Context and problem statement

A convenience `thoughtmark` umbrella crate re-exporting every plugin would let cross-workspace feature unification
silently pull host entropy (`getrandom/js`, `ed25519-dalek/rand_core`) or networking into the `no_std` core — the
most insidious failure mode (arch P1/§2.2).

## Decision outcome

**No umbrella meta-crate in v1.** Consumers depend on the explicit plugin crates they want. The graph stays
legible for `cargo-deny`/`cargo-vet`, and the dependency-direction check (`scripts/check-dep-direction.sh`) can
assert that core's closure contains no plugin/networking/entropy crate.

## Consequences

- Slightly more verbose downstream `Cargo.toml`s; far safer feature unification.
- `cargo hack --feature-powerset` proves all feature combinations build without leaking forbidden deps.
