<!-- Phase 0 quality contract: a PR cannot merge until `just ci` is green (CI is authoritative). -->

## What & why

<!-- One paragraph. Link the SPEC.md requirement ID(s) and/or ADR(s) this realizes. -->

## Definition of Done (check before requesting review)

- [ ] `just ci` is green locally (fmt, clippy `-D warnings`, nextest, **conformance**, deny, audit, tsc, biome, wasm tests).
- [ ] New behavior is covered by `spec/vectors/` entries **and** the cross-language conformance job stays byte-identical (Rust ⟷ WASM/TS).
- [ ] No new ambient nondeterminism (`SystemTime::now`, `thread_rng`, …) and no floats on the canon/hash/CID/merkle path.
- [ ] No hand-rolled crypto; Ed25519 verification uses `verify_strict`.
- [ ] Public-API changes pass `cargo-semver-checks`; docs build with no `missing_docs`.
- [ ] New dependencies pass `cargo deny check` and have a `cargo vet` entry.
- [ ] I did not weaken a lint, a `deny.toml` rule, a hook, or a CI gate. Edits to `.claude/**`, `.github/**`, `deny.toml`, `rust-toolchain.toml` were reviewed by a human.

## Integrity, not validity

- [ ] This change does not let green CI be misread as a claim about the **content** being notarized (integrity-of-record only; see `docs/threat-model.md`).
