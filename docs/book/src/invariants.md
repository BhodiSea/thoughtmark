# Invariants (I1–I8)

- **I1** Byte-identical output across Rust core, WASM, and TS (the conformance corpus is the oracle).
- **I2** Always JCS-canonicalize before hashing (`serde_json_canonicalizer`; `serde_jcs` banned).
- **I3** No ambient nondeterminism in core (no `SystemTime::now`/`thread_rng`; inject time/RNG).
- **I4** No floating point on the canon/hash/CID/merkle path.
- **I5** Salted hashes only; never store sensitive content or put content on any chain.
- **I6** Audited crypto only; Ed25519 `verify_strict` always.
- **I7** Integrity-of-record, not validity, not faithfulness.
- **I8** Pure, layered, dependency-light, audited core.
