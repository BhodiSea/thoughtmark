---
paths:
  - "**/tests/**"
  - "**/*.test.ts"
  - "crates/thoughtmark-testkit/**"
---
# Testing discipline
- NEVER mutate, `.skip()`, or `#[ignore]` a test to make it pass. A red test is information, not an obstacle.
- The cross-language conformance suite is the load-bearing test: it asserts byte-equality of Rust <-> WASM/TS over
  every `spec/vectors/` case. Both runtimes must read the SAME corpus (single `THOUGHTMARK_VECTORS` source) and
  assert equal vector counts.
- New behavior needs: a `spec/vectors/` entry, a proptest property where one applies (idempotence, stability), and
  an example/snapshot test. Negative vectors assert the exact stable `ErrorCode`.
- Tests are deterministic: inject `FixedClock`/`SeededRng` (the `vectors` feature), never ambient time/RNG.
