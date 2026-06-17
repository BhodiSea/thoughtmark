---
paths:
  - "crates/**/crypto/**/*.rs"
  - "crates/**/canon*.rs"
  - "crates/**/hash*.rs"
  - "crates/**/cid*.rs"
  - "crates/**/merkle/**/*.rs"
  - "crates/**/dsse*.rs"
  - "crates/**/sign*.rs"
---
# Crypto & canonicalization invariants
- Canonicalize via `serde_json_canonicalizer` (RFC 8785) before any hash. Never re-implement JCS. `serde_jcs` is BANNED (ADR-0001).
- BLAKE3 (`blake3`) is the internal default; SHA-256 (`sha2`) for interop. Both must be in the vectors.
- Ed25519 via `ed25519_dalek`, verification ALWAYS `verify_strict` (never bare `verify`).
- No floats; no `SystemTime`/`thread_rng`. Wrap secrets in `secrecy::Secret`, wipe with `zeroize`, compare with `subtle`.
- No ambient nondeterminism: time enters as `Clock::now() -> UnixMillis`, randomness as injected `Rng`/`Csprng`.
- Every new primitive ships with authoritative test vectors (Wycheproof / RFC) AND a `spec/vectors/` entry.
- Changing any expected hash in `spec/vectors/` is a BREAKING spec change (MAJOR corpus release + CHANGELOG).
