<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows SemVer. The conformance corpus is
versioned separately in [`spec/vectors/VERSION`](spec/vectors/VERSION).

## [Unreleased] — Phase 0: Foundations & Quality Spine

### Added

- Monorepo skeleton: Cargo workspace (`resolver = "3"`, edition 2024, Rust 1.96.0) + pnpm workspace, with the
  single seam `thoughtmark-wasm` → `@thoughtmark/core`.
- The entire gate net against stub crates: pinned toolchain, `[workspace.lints]` no-panic wall + `forbid(unsafe)`,
  `clippy.toml` nondeterminism/no-float bans, `deny.toml`, cargo-vet, the dependency-direction and wasm32
  no-leak assertions.
- **The cross-language conformance gate** (row 10): native Rust + WASM-under-Node assert byte-equality over
  `spec/vectors/` (stubs agree on `NOT_IMPLEMENTED`).
- Agent harness lock-down (`CLAUDE.md`, `.claude/` settings/rules/agent/skill/hooks, managed-settings template).
- Day-one ADRs 0001–0006; threat model; SPEC.md; licensing (SPDX/REUSE/NOTICE); SECURITY/CONTRIBUTING/CITATION;
  CI workflows; mdBook skeleton.
