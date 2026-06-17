---
name: verify-determinism
description: Run the full cross-language conformance suite and assert byte-identical Rust <-> WASM/TS output.
when_to_use: Before any commit touching canonicalization, hashing, CID, the Merkle log, or the bindings.
disable-model-invocation: false
user-invocable: true
allowed-tools: Bash
---
1. `cargo nextest run -p thoughtmark-testkit --test conformance`
2. `pnpm --filter @thoughtmark/core test:conformance`
3. Compare both runs' outputs against `spec/vectors/`; FAIL on any byte divergence and print the first mismatch.
