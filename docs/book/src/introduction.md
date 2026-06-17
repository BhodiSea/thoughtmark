# Introduction

thoughtmark is a tamper-evident provenance library for human–AI reasoning trails. A pure, audited Rust core
(`thoughtmark-core`) compiles to WASM/TypeScript bindings (`@thoughtmark/core`) that are **byte-identical** to the
native core, validated by a versioned conformance corpus (`spec/vectors/`).

This guide is built with mdBook in CI. Phase 0 ships the quality spine and stubs; Tier-0 logic (canon/hash/CID)
lands in Phase 1. See [SPEC.md](https://github.com/OWNER/thoughtmark/blob/main/spec/SPEC.md) for the normative
requirements.
