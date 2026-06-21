# Conformance corpus — CHANGELOG

The corpus is versioned independently from the code (its own SemVer in `VERSION`). This log is **append-only**.
**Changing any expected value (e.g. an expected hash or expected bytes) is a BREAKING change** and requires a
MAJOR corpus release. Three version axes are never conflated: code SemVer, corpus SemVer, and the format
identifiers baked into hashed bytes (arch P4).

## [0.9.0] — `verify()` red-team gate-net vectors (additive)

Adds 15 `verify` op vectors (`verify/0005`–`verify/0019`) that close the negative-path coverage gap a Linus-level
red team found in the 0.8.0 corpus: of the nine checks, only `DsseSignature`/`AnchorReceipt`/`ContributionLineage`
had a failing vector, so the k-of-n threshold, the tree-size binding, the `expected_subject_digest` gate, and the
lineage DAG's structural failure modes were mutation-dead. **Additive only — no pre-existing expected byte changed**
(`vector_count` 111 → 126), a MINOR release. Every failure case isolates exactly ONE check and is a positive vector
(a tamper is a *successful run with `total:false`*, never an error envelope).

- **`verify/0005` (POLICY-1) — k-of-n 2-of-2 PASS.** Two DISTINCT trusted log keys cosign one checkpoint;
  `required_witnesses:2` ⇒ `Checkpoint` passes with `detail.matched:2, required:2` (pins distinct-key counting and
  the `max(1, required)` floor for `n>1`).
- **`verify/0006` (VERIFY-3) — `BundleSchema`** fails `BUNDLE_VERSION_UNSUPPORTED` (unsupported `bundle_version`).
- **`verify/0007` (VERIFY-3) — `CanonVersion`** fails `UNKNOWN_CANON_VERSION` (canon not in `accepted_canon_versions`).
- **`verify/0008`–`0011` (VERIFY-3) — `StatementBinding`** fails `STATEMENT_SUBJECT_MISMATCH` four ways: a corrupted
  subject digest; a bound `tree_size` ≠ the inclusion proof's; a policy `expected_subject_digest` mismatch; and a
  non-singleton `subject` set.
- **`verify/0012`, `0016` (VERIFY-3) — `MerkleInclusion`** fails `MERKLE_PROOF_INVALID`: a leaf not under the
  (re-signed) checkpoint root, and a signed checkpoint `size` ≠ the proof `tree_size`.
- **`verify/0013`–`0015` (VERIFY-3/POLICY-1) — `Checkpoint`** fails `CHECKPOINT_SIGNATURE_INVALID`: an untrusted log
  key, a k-of-n shortfall (`required_witnesses:2`, one cosignature), and a policy `log_origin` mismatch.
- **`verify/0017`–`0019` (VERIFY-3) — `ContributionLineage`** fails `LEDGER_BROKEN_LINK`: a declared turn with no
  stapled body (mandatory lineage), a duplicate stapled body, and a `run_manifest_ref` with no stapled manifest.

## [0.8.0] — `verify()` pipeline vectors (additive)

Adds the first `verify` op vectors (arch §11, Phase 3): the offline `verify()` orchestrator over a stapled
`ThoughtmarkBundle`, pinning the JCS-canonical `VerificationResult` bytes native Rust ⟷ WASM/TS. **Additive only —
no pre-existing expected byte changed** (`vector_count` 106 → 111), a MINOR release. The `verify` op's injected
`now` is carried INSIDE each case's `input.json` (an `env.now_unix_ms` field), so cases remain pure functions of
their `input` bytes; a tamper is a *successful run with `total:false`*, so the verify failure cases are positive
vectors (full expected `VerificationResult`), not error-envelope negatives.

- **`verify/0001` (VERIFY-1) — all-pass.** A signed two-turn trail (AI `create` + human `approve`, with a stapled
  run manifest): every required check passes, `total:true`, `Established.lineage` is populated, the constant
  `NotEstablished` honesty frame (I7) is present, `Consistency`/`AnchorReceipt` are `Skipped` (inert at 1.0).
- **`verify/0002` (VERIFY-2) — tampered signature.** One signature byte flipped: `DsseSignature` fails
  `SIG_INVALID` and `unaltered_since_capture` is `false`, but `StatementBinding`/`MerkleInclusion`/`Checkpoint`/
  `ContributionLineage` still pass on the intact record — the honesty report survives a `total:false` run (one
  failure never masks another).
- **`verify/0003` (POLICY-1) — `require_anchor` fails closed.** With `require_anchor:true` and no anchor present
  (no `AnchorVerifier` ships until Phase 4), `AnchorReceipt` fails and `existed_at_or_before` stays `null`.
- **`verify/0004` (POLICY-1) — required action absent.** A `Policy.required_actions` not in the ledger →
  `ContributionLineage` fails `POLICY_UNSATISFIED`.
- **`negative/0044` (VERIFY-1) — malformed verify input** → `BUNDLE_SCHEMA_INVALID` (the one true error-envelope
  case: malformed INPUT, not a tamper).
- `bundle/0001` and `negative/0016` **inputs** were regenerated to the real two-turn bundle (their expected
  outputs — `ok.txt` / `BUNDLE_SCHEMA_INVALID` — are unchanged), so this remains additive.

## [0.7.0] — Authoritative external vectors + large-tree Merkle (additive)

Imports published third-party test corpora so the corpus is no longer self-blessed from the same core it validates
(the "authoritative vectors imported" gate, quality-foundations Domain 6 #20). Every imported case's expected
value/result comes from the UPSTREAM source; our core's output was asserted against it via `tm bless --check` and
independently reproduced by the pure-TS oracle (executor D) — all 106 cases agree across native Rust, WASM/Node, and
the oracle. **Additive only — no pre-existing expected byte changed** (`vector_count` 51 → 106), a MINOR release.

- **Ed25519 (I6) — RFC 8032 + ed25519-speccheck + Wycheproof** (`ed25519/0002-0010` accept, `negative/0017-0039`
  reject, SIG-1): the 5 RFC 8032 §7.1 known-answer vectors; the ed25519-speccheck "Taming the many EdDSAs" matrix
  classified by the authoritative **Dalek-strict** column (only the mixed-order vector 3 / `ed25519/0007` is a
  strict-accept); and a curated Wycheproof v1 subset of signature-malleability / non-canonical-S / small-order-R /
  non-canonical-R cases. Classified by **cofactorless `verify_strict`** semantics (= our core).
  - **Oracle correctness fix (executor D):** the pure-TS oracle previously verified Ed25519 with
    `@noble/curves` `{ zip215: false }`, which the [0.4.0] note called "the `verify_strict` equivalent" — that was
    **incorrect**. noble's `zip215:false` checks the COFACTORED equation and does NOT reject a small-order `R`, so
    it wrongly accepts the small-order-`R` malleability vectors (speccheck #4/#5, Wycheproof `R==0`). The oracle now
    implements a faithful cofactorless `verify_strict` (reject small-order `A` **or** `R`; canonical `S < L`;
    `[S]B − [k]A == R`), cross-checked to reproduce the speccheck Dalek-strict matrix and every RFC 8032 /
    Wycheproof-v1 / corpus case. This is an oracle **code** fix; no expected byte moved. The new small-order-R
    vectors are precisely what exposed the latent gap — a second implementation only proves self-consistency unless
    anchored to the external standard (cf. the [0.6.1] checkpoint lesson).
  - **`SIG_INVALID` vs `SIG_MALFORMED_KEY`:** a small-order or non-canonical-but-decodable public key is admitted by
    `ed25519-dalek::VerifyingKey::from_bytes` and rejected only at `verify_strict`, so our core returns
    **`SIG_INVALID`** (not `SIG_MALFORMED_KEY`) for those — confirmed by probing the core. `SIG_MALFORMED_KEY` is
    reserved for a wrong-length / undecodable (off-curve) key. All 23 negatives are fail-closed regardless.
- **RFC 8785 JCS — cyberphone/json-canonicalization** (`canon/0005-0008` positive, `negative/0041-0043`, CANON-1/3/4):
  the upstream `arrays`/`french`/`unicode`/`weird` canonical outputs, used VERBATIM as `expected.bin` — our in-house
  encoder reproduces them byte-for-byte, including the **`weird` UTF-16 surrogate-pair + control-char key sort** (the
  exact ordering `serde_jcs` got wrong). Upstream float cases (`values`, `structures` with `56.0`) and the documented
  `2^53+2` integer become NEGATIVES under thoughtmark's integer-only JCS profile (I4): `CANON_NON_DETERMINISTIC_FLOAT`
  / `CANON_INTEGER_OUT_OF_RANGE`.
- **multiformats CID** (`cid/0002-0004`, CID-1): RAW-codec (`0x55`) + BLAKE3-256 (`0x1e`) CIDv1 for the blobs
  `<empty>` / `"hello world"` / `0x00..0x0f`, computed with the real `multiformats` + `@noble/hashes` libraries (the
  same the oracle consumes) — an independent third-party reference.
- **DSSE PAE — secure-systems-lab** (`dsse/0004-0006`, SIG-2): the go-securesystemslib `TestPAE` "Empty"
  (`DSSEv1 0  0 `) and "Unicode-only" (LEN counts bytes not chars) vectors verbatim, plus an in-toto/SLSA
  `application/vnd.in-toto+json` Statement PAE.
- **RFC 6962 Merkle — transparency-dev/merkle** (`merkle/0008-0014`, LOG-1): the certificate-transparency reference
  tree roots for sizes 2–8 over leaves `d0..d7` (the canonical 8-entry CT reference tree at `merkle/0014`), matched
  byte-for-byte by our `merkle_root`.
- **Large-tree Merkle (cross-language agreement at scale)** (`merkle/0007`, `inclusion/0004`, `consistency/0004`,
  LOG-1/2/3): a **1000-leaf** non-power-of-two tree with a depth-~10 inclusion proof and a 700→1000 consistency
  proof. Blessed from the core and independently reproduced by the oracle's RFC 9162 iterative verifiers — pinning
  byte-agreement on a wide, odd-sized tree whose left/right split structure the ≤8-leaf cases never exercise. (This
  is a scale/shape vector, not a stack-exhaustion test: depth ~10 is trivial stack; the verifiers' constant-stack
  property is structural, not something a depth-10 vector demonstrates.)
- **Determinism note:** every case is a pure function of its `input`; signing determinism is supplied inline
  (`seed_hex` → `TmSigner::from_seed`), so no per-case `env`/`FixedClock`/`VectorCsprng` is needed (manifest
  `description`).

## [0.6.1] — Phase 2 red-team: C2SP signed-note conformance fix (input-only)

- **Bug:** the checkpoint note format omitted the **mandatory blank-line separator** that
  [c2sp.org/signed-note](https://c2sp.org/signed-note) requires between the signed text and the signature block
  ("a text ending in newline, followed by a blank line, followed by one or more signature lines"). The note glued
  the `— …` signature line directly onto the body. This made the notes un-parseable by every other signed-note
  implementation (sigsum / Go checksum DB / sunlight) and made `verify_checkpoint` reject every real checkpoint
  (it would fold the blank line into the signed text). LOG-4 ("MUST be a C2SP signed note") was violated. The
  independent pure-TS oracle did not catch it because it **mirrored** the Rust note layout rather than the real
  format — the lesson being that a second implementation only proves self-consistency unless it is anchored to the
  external standard.
- **Fix:** `sign_checkpoint` now emits the blank-line separator; `verify_checkpoint` splits the note at the first
  `\n\n` and signs/verifies over the text **including its final newline but excluding the blank line**. The TS
  oracle was updated to the same (independently re-derived) split.
- **No expected value changed.** The actually-signed bytes are `checkpoint_body`, which was already correct
  (`origin "\n" size "\n" base64(root) "\n"`), so `checkpoint/0001` and every `checkpoint_verify` **output** are
  byte-identical. Only the `note_b64` **inputs** of `checkpoint/0002`, `negative/0014`, and `negative/0015` were
  regenerated to be valid C2SP notes. `vector_count` stays 51. Because no expected byte moved, this is a **PATCH**
  corpus release, not a breaking one. New focused Rust tests (`tests/checkpoint.rs`) pin the blank-line contract so
  the regression cannot recur.

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
