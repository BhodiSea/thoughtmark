# Conformance corpus — CHANGELOG

The corpus is versioned independently from the code (its own SemVer in `VERSION`). This log is **append-only**.
**Changing any expected value (e.g. an expected hash or expected bytes) is a BREAKING change** and requires a
MAJOR corpus release. Three version axes are never conflated: code SemVer, corpus SemVer, and the format
identifiers baked into hashed bytes (arch P4).

## [0.1.1] — Phase 1: arm the UTF-16 key-sort guard (additive)

- **Added `canon/0004`** (CANON-3): `{"￿":1,"😀":2}` → `{"😀":2,"￿":1}`. This is the first vector that
  actually **discriminates** UTF-16 code-unit order from code-point / UTF-8 byte order. The prior astral case
  `canon/0003` (`😀` vs `z`) sorts identically under all three orders, so it could not catch a regression to
  code-point sorting — the exact class that killed `serde_jcs`. With `U+FFFF` vs `U+1F600`: under UTF-16, `😀`
  (`D83D…`) sorts **before** `￿` (`FFFF`); under code-point / UTF-8, `￿` sorts first. A non-UTF-16 sort now fails
  this vector across every executor (native Rust, WASM/Node, and the independent `cyberphone/canonicalize` oracle).
- **Additive only** — no existing expected byte changed (`vector_count` 12 → 13), so this is a MINOR corpus release,
  not a breaking one.

## [0.1.0] — Phase 1: real Tier-0 corpus

- **Layout migrated** from inline `expected_bytes_b64` JSON to the directory-per-case raw-file layout (arch §13.2):
  `canon/NNNN/` (`input.json` → `expected.bin`), `hash/NNNN/` (`input.json` → `blake3.hex` + `sha256.hex`),
  `cid/NNNN/` (`input.bin` → `expected.txt`), `domain/NNNN/` (`input.json` → `expected.hex`), `negative/NNNN/`
  (`input.json` → `expected_code.txt`). `manifest.json` now lists one entry per `run_op(op, input)` call with a
  `vector_count` for cross-language count parity.
- **Real expected output**, blessed once from the native Rust core (`tm bless`) and frozen. Covers: object-key
  sort (CANON-1), non-ASCII + astral-plane UTF-16 key sort (CANON-3, the `serde_jcs`-killer guard), BLAKE3 +
  SHA-256 over canonical bytes (HASH-1), CIDv1 base32-lower (CID-1), domain-separated hash binding
  `CANON_VERSION` (HASH-2).
- **Negative cases** (CANON-4 / CANON-1), each asserting a stable fail-closed `ErrorCode`: finite float →
  `CANON_NON_DETERMINISTIC_FLOAT`; `NaN` / `Infinity` tokens → `CANON_INVALID_JSON`; duplicate key →
  `CANON_INVALID_JSON`; `2^53 + 1` → `CANON_INTEGER_OUT_OF_RANGE`.
- **Hashing preimage** pinned: plain `hash_*` is `H(canonicalize(input))` (no domain prefix); `hash_domain_*` is
  `H(CANON_VERSION ":" alg ":" domain ":" || canonical_json)`.
- Canonicalization is implemented in-house (`canon::jcs`); `serde_json_canonicalizer` + the pure-TS
  `cyberphone/canonicalize` are independent differential oracles (ADR-0001 as amended).

## [0.0.0] — Phase 0

- Initial skeleton. Every operation's expected output was the canonical `NOT_IMPLEMENTED` envelope; the gate had
  teeth against stubs before any real Tier-0 logic landed.
