# Conformance corpus — CHANGELOG

The corpus is versioned independently from the code (its own SemVer in `VERSION`). This log is **append-only**.
**Changing any expected value (e.g. an expected hash or expected bytes) is a BREAKING change** and requires a
MAJOR corpus release. Three version axes are never conflated: code SemVer, corpus SemVer, and the format
identifiers baked into hashed bytes (arch P4).

## [0.6.0] — Phase 2 (M5): the ThoughtmarkBundle corpus (additive)

- **`bundle_check`** (`bundle/0001`, BUNDLE-1): a COMPLETE assembled bundle — a DSSE-signed in-toto Statement, its
  Merkle inclusion proof, and a signed C2SP checkpoint, with offline `verification_material` — passes the
  structural gate (`media_type = application/vnd.thoughtmark.bundle.v1+json`, `bundle_version = 1`,
  `canon_version = tm-jcs-1`). A wrong media type fails closed with `BUNDLE_SCHEMA_INVALID` (`negative/0016`).
- This is the **structural** gate only; the full cryptographic `verify()` (replaying the inclusion proof,
  checkpoint signature, and DSSE envelope) is a later phase. `tm bundle-check FILE` exposes it on the CLI.
- The `core::anchor` seam types (`AnchorReceipt`/`AnchorKind`/`AnchorStatus`/`AnchorVerdict`/`CheckpointRef` +
  `AnchorVerifier` trait, opaque `proof` bytes) land as types-only (ADR-0008); `bundle.anchors` stays empty until a
  later phase populates it.
- **Additive only** — `vector_count` 49 → 51, a MINOR corpus release. This completes the four frozen
  format-identifier values (`predicateType`, `canon_version`, DSSE `payloadType`, bundle `media_type`).

## [0.5.0] — Phase 2 (M4): the C2SP checkpoint corpus (additive)

- **`checkpoint_body`** (`checkpoint/0001`, LOG-4): the deterministic signed-note text body
  (`origin "\n" size "\n" base64(root) "\n"`). **`checkpoint_verify`** (`checkpoint/0002`, LOG-4) verifies a signed
  note and returns the canonical parsed `Checkpoint`.
- **The two exactness-trap negatives** (LOG-4, both → `CHECKPOINT_SIGNATURE_INVALID`): a **hyphen in place of the
  em-dash** signature-line prefix (`negative/0014`) — the prefix is U+2014 + space, never `-`; and a signature for
  a **different keyname** (`negative/0015`) — `verify_checkpoint` requires ≥1 line to actually match a known key,
  since the note spec mandates ignoring unknown signatures.
- The key-hash is `SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ pubkey32)[..4]`. The pure-TS oracle (executor D) re-parses the
  note byte-for-byte and re-verifies via `@noble/curves`, agreeing with the Rust core on both traps.
- **Additive only** — `vector_count` 45 → 49, a MINOR corpus release. (Also: `core::merkle::tiles` lands the
  tlog-tiles `parse_tile` + the `x`-prefixed index path encoder, core-unit-tested.)

## [0.4.0] — Phase 2 (M3): the DSSE / Ed25519 / did:key signing corpus (additive)

- **Ed25519 `verify_strict`** (`ed25519/0001` accept, SIG-1) plus the **malleability/cofactor reject boundary**
  (`negative/0011`, SIG-1): a non-canonical scalar `S' = S + ell` — the exact cofactor-8 malleability that
  `verify_strict` closes (bare `verify` would accept it) — fails closed with `SIG_INVALID`. Also a tampered
  signature → `SIG_INVALID` (`negative/0012`) and a too-short public key → `SIG_MALFORMED_KEY` (`negative/0013`).
- **DSSE PAE** (`dsse/0001`, SIG-2): the canonical DSSE spec example —
  `DSSEv1 29 http://example.com/HelloWorld 11 hello world` — pinning the `itoa` byte-length framing.
- **Deterministic `sign_statement`** (`dsse/0002`, SIG-5): a fixed seed signs a canonical Statement → a canonical
  DSSE envelope (one signature, ADR-0007). **`dsse_verify_envelope`** (`dsse/0003`, SIG-3) round-trips it back to
  the payload. **`did_key_decode`** (`did/0001`, SIG-4) decodes a `did:key:z6Mk…` to its public key.
- **Independent cross-check**: the pure-TS oracle (executor D) verifies via `@noble/curves` ed25519 with
  `{ zip215: false }` (RFC 8032 strict, the `verify_strict` equivalent) — it independently REJECTS the
  non-canonical-`S` variant and reproduces the deterministic `sign_statement` envelope byte-for-byte. Two
  independent Ed25519 implementations agree on the malleability boundary.
- **Additive only** — no existing expected byte changed (`vector_count` 37 → 45), a MINOR corpus release. (Build
  detail: core moved to `sha2` 0.10 + portable BLAKE3 to match the audited dalek stack — identical hash output, no
  re-bless.)

## [0.3.0] — Phase 2 (M2): the RFC 6962 / RFC 9162 Merkle corpus (additive)

- **Added Merkle tree-hash vectors** (`merkle/0001-0006`, LOG-1/LOG-2, op `merkle_root` → base64 root): empty,
  single, power-of-two (4, 8), and **non-power-of-two (5, 7)** trees — the latter pin the
  strict-largest-power-of-two split (a naive `n/2` split is a classic bug that passes only on powers of two). The
  empty root is the base64 of `SHA-256("")`; a `TreeHash` is base64, deliberately distinct from a content `Digest`
  (ADR-0013).
- **Added inclusion-proof vectors** (`inclusion/0001-0003`, LOG-2, op `merkle_verify_inclusion` → `{"ok":true}`)
  and **consistency-proof vectors** (`consistency/0001-0003`, LOG-3, op `merkle_verify_consistency`), generated
  from the validated core (`THOUGHTMARK_EMIT_MERKLE=1`) over middle/first/last leaves and pow2/non-pow2 prefixes.
- **Added Merkle negative cases** (fail-closed parity across all four executors): a mutated audit-path element
  (`negative/0008`) and a too-long audit path — the proof-padding forgery vector (`negative/0009`) — both →
  `MERKLE_PROOF_INVALID`; a consistency proof against a tampered `new_root` (`negative/0010`) →
  `CONSISTENCY_PROOF_INVALID`.
- **Independent cross-check**: the pure-TS oracle (executor D) re-implements RFC 6962/9162 from `@noble/hashes`
  alone (its own leaf/node hashing, streaming tree hash, and iterative inclusion/consistency verifiers) and agrees
  with the Rust core byte-for-byte on every case.
- **Additive only** — no existing expected byte changed (`vector_count` 22 → 37), a MINOR corpus release.

## [0.2.0] — Phase 2 (M1): the `Provenance/v1` schema corpus (additive)

- **Added the reasoning-trail schema vectors** (the §5.11 MedQBank worked example, with real opaque off-ledger
  commitments in place of the doc's truncated placeholders): `turn/0001` + `turn/0002` (SCHEMA-2, op
  `hash_domain_turn` — `turn_id`), `manifest/0001` (SCHEMA-2, op `hash_domain_manifest` — `manifest_id`),
  `trail/0001` (SCHEMA-3, the new `trail_root` op — the dual `{"blake3","sha256"}` digest map), and
  `statement/0001` (SCHEMA-4, op `canonicalize` — an in-toto `Statement` wrapping the trail at `tree_size = 2`).
- **Added schema negative cases** (SCHEMA-1, fail-closed parity across all four executors): a float
  `temperature_milli` → `CANON_NON_DETERMINISTIC_FLOAT` (`negative/0006`); a `sequence` at `2^53` →
  `CANON_INTEGER_OUT_OF_RANGE` (`negative/0007`).
- **New op `trail_root`**: canonicalize a trail, then emit `{"blake3":hex,"sha256":hex}` over the
  `thoughtmark.object` domain with both algorithms (the one schema derivation needing both digests). It stays
  raw-JSON so `core::ops` never depends on `thoughtmark-schema`. The independent pure-TS oracle re-derives it.
- **Additive only** — no existing expected byte changed (`vector_count` 15 → 22), so this is a MINOR corpus
  release. The typed `thoughtmark-schema` structs round-trip byte-identically to these fixtures (the worked-example
  tests `include_str!` the corpus so the two can never drift).

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
