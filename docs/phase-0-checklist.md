<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase 0 exit checklist — 27 `[MUST]` rows → the files that satisfy them

Mirrors the qf bootstrap checklist. **Status** is the local result of `just ci` (green against stub crates) plus
the server-side items deferred to [BOOTSTRAP.md](../BOOTSTRAP.md). ✅ = wired & green locally; 📋 = authored,
applied server-side via BOOTSTRAP.md (no remote yet); ⏳ = wired, activates in a later phase per the activation rule.

| # | `[MUST]` control | File(s) | CI mirror | Status |
|---|------------------|---------|-----------|--------|
| 1 | Agent codebook & invariants | [CLAUDE.md](../CLAUDE.md), [.claude/rules/](../.claude/rules/) | — | ✅ |
| 2 | Permissions / sandbox / harness lock-down | [.claude/settings.json](../.claude/settings.json), [.claude/managed-settings.json](../.claude/managed-settings.json) | — (org-applied) | ✅ / 📋 |
| 3 | Blocking + format hooks | [.claude/hooks/guard-bash.sh](../.claude/hooks/guard-bash.sh), [.claude/hooks/fmt-lint.sh](../.claude/hooks/fmt-lint.sh) | `ci.yml` (same checks) | ✅ |
| 4 | Pinned toolchain | [rust-toolchain.toml](../rust-toolchain.toml) | `ci.yml` matrix | ✅ |
| 5 | Deny-warnings + lints + forbid-unsafe | [Cargo.toml](../Cargo.toml) `[workspace.lints]` | `clippy -D warnings` | ✅ |
| 6 | Ban nondeterminism | [clippy.toml](../clippy.toml) `disallowed-methods` | clippy job | ✅ |
| 7 | Dependency policy + audit + provenance | [deny.toml](../deny.toml), [supply-chain/](../supply-chain/) (cargo-vet) | `cargo deny`/`audit` | ✅ |
| 8 | Test runner + property tests | nextest + `proptest` (core dev-deps) | `cargo nextest` | ✅ (proptest ⏳) |
| 9 | Fuzz targets | [fuzz/](../fuzz/) (cargo-fuzz, outside workspace) | nightly-fuzz.yml | ⏳ (per-parser) |
| 10 | **Cross-language conformance corpus + gate** ⭐ | [spec/vectors/](../spec/vectors/) + [native](../crates/thoughtmark-testkit/tests/conformance.rs) & [Node](../packages/core/test/conformance.test.ts) runners | **`conformance` job** | ✅ |
| 11 | No floats in hash path | [clippy.toml](../clippy.toml) `disallowed-types` + `float_arithmetic` | clippy job | ✅ |
| 12 | Strict TS + typecheck | [tsconfig.base.json](../tsconfig.base.json) | `tsc --noEmit` | ✅ |
| 13 | TS lint/format | [biome.json](../biome.json) | `biome check` | ✅ |
| 14 | WASM tests + package correctness | [packages/core/package.json](../packages/core/package.json), wasm-bindgen-test | `ts-wasm` job | ✅ (browser ⏳ CI) |
| 15 | SHA-pinned, hardened Actions | [.github/workflows/](../.github/workflows/) | `actions-hardening` job | 📋 (pinact, BOOTSTRAP) |
| 16 | Rulesets: signed commits, required checks, tag protection | repo ruleset | enforced by GitHub | 📋 (BOOTSTRAP §3) |
| 17 | Local gates == CI | [lefthook.yml](../lefthook.yml), [justfile](../justfile) | `just ci` == `ci.yml` | ✅ |
| 18 | Repo hygiene | [.editorconfig](../.editorconfig), [.gitignore](../.gitignore), [.gitattributes](../.gitattributes), [CODEOWNERS](../CODEOWNERS) | — | ✅ |
| 19 | Audited crypto + constant-time + key hygiene | [Cargo.toml](../Cargo.toml) `[workspace.dependencies]` + [crypto-invariants rule](../.claude/rules/crypto-invariants.md) | clippy/tests | ✅ (pins; logic Phase 1+) |
| 20 | Authoritative vectors | [spec/vectors/](../spec/vectors/) (Wycheproof/RFC seeded Phase 2) | `conformance` job | ⏳ (Phase 2) |
| 21 | Secret scanning | [gitleaks.yml](../.github/workflows/gitleaks.yml) + push protection | `gitleaks` job | ✅ / 📋 |
| 22 | Threat model | [docs/threat-model.md](threat-model.md) | review gate | ✅ |
| 23 | Reproducible builds | [Cargo.toml](../Cargo.toml) profile, [Cargo.lock](../Cargo.lock), pinned wasm-opt | rebuild-and-diff (release.yml) | ✅ (trim-paths ⏳) |
| 24 | Normative spec + traceability | [spec/SPEC.md](../spec/SPEC.md) | [spec-traceability.sh](../scripts/spec-traceability.sh) | ✅ |
| 25 | JCS-crate decision recorded | [docs/adr/0001-jcs-crate.md](adr/0001-jcs-crate.md) | — | ✅ |
| 26 | Licensing compliance | SPDX headers + [NOTICE](../NOTICE) + [REUSE.toml](../REUSE.toml) | `reuse lint` | ✅ |
| 27 | Disclosure + contribution policy | [SECURITY.md](../SECURITY.md), [CONTRIBUTING.md](../CONTRIBUTING.md) | — | ✅ |

## Day-one ADRs recorded

[0001](adr/0001-jcs-crate.md) (JCS crate; `serde_jcs` banned), [0002](adr/0002-one-core-plus-schema.md),
[0003](adr/0003-just-pnpm-no-turborepo.md), [0004](adr/0004-no-umbrella-meta-crate.md),
[0005](adr/0005-reimplement-rfc6962.md), [0006](adr/0006-fuzz-outside-workspace.md).

## The dependency-direction & no-leak assertions (I8, arch §3.3 / P1)

[scripts/check-dep-direction.sh](../scripts/check-dep-direction.sh) and
[scripts/assert-no-getrandom-wasmbindgen.sh](../scripts/assert-no-getrandom-wasmbindgen.sh) run in `ci-rust`;
both green (core depends only inward; no `getrandom`/`wasm-bindgen` on the wasm32 core build).
