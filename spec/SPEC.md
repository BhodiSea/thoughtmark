# thoughtmark — Normative Specification

**Status:** Phase 2 — **wire-format freeze CANDIDATE**. The four format-identifier values are implemented and
pinned across all four conformance executors (native Rust, WASM/Node, the pure-TS oracle, and — once the human
wires the CI job — WASM/3-browsers): `canon_version = "tm-jcs-1"`,
`predicateType = "https://thoughtmark.dev/Provenance/v1"`, DSSE `payloadType = "application/vnd.in-toto+json"`,
and bundle `media_type = "application/vnd.thoughtmark.bundle.v1+json"`. From here, changing any hashed byte
requires a NEW format-identifier value + a MAJOR corpus release (add `canon_v2`, never mutate `canon_v1`).
**License:** Apache-2.0.

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**,
**RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in BCP 14
([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

## 2. What this specification establishes (and what it does not)

This specification defines **integrity-of-record**: that a record existed at a time, in a lineage, and is
unaltered since capture; that a log is append-only; and that a signature binds a record to a signer's key.
It does **NOT** establish **validity** (that the content is true), **faithfulness** (that a logged reasoning
trail reflects the computation that produced it), split-view resistance without external witnesses, or
truth-at-capture. See [`docs/threat-model.md`](../docs/threat-model.md). Conformance to this spec MUST NOT be
represented as a claim about the content being notarized.

## 3. Requirements and traceability

Every normative requirement has a **stable ID** (`AREA-N`). Each ID is traced **bidirectionally** to the
conformance corpus: every requirement that is testable MUST have at least one `spec/vectors/` case whose
`spec_req` equals its ID, and every vector's `spec_req` MUST name a requirement defined here. CI enforces this
(`scripts/spec-traceability.sh`).

Output byte-identity is the master requirement:

- **CORE-1** — For identical logical input, every implementation (Rust core, WASM, TypeScript) **MUST** produce
  byte-identical output. The `spec/vectors/` corpus is the oracle.
- **CORE-2** — An operation that fails **MUST** return the canonical error envelope (Section 4) carrying a stable
  `ErrorCode`, byte-identically across implementations (fail-closed).

### 3.1 Canonicalization (CANON)

- **CANON-1** — JSON intended for hashing **MUST** be canonicalized per RFC 8785 (JCS) before hashing; bare
  `H(json)` is forbidden.
- **CANON-2** — Canonicalization **MUST** be performed by the single choke point
  (`thoughtmark_core::canon::jcs`, an in-house RFC 8785 encoder — the `std`-only `serde_json_canonicalizer` cannot
  run in the `no_std` WASM core). `serde_jcs` **MUST NOT** be used. `serde_json_canonicalizer` and an independent
  pure-TS oracle serve as differential checks only (ADR-0001, as amended).
- **CANON-3** — Object members **MUST** be ordered by UTF-16 code unit of the member name, per RFC 8785.
- **CANON-4** — Floating-point numbers **MUST NOT** appear on the canonicalization path; integers outside the
  I-JSON safe range **MUST** be carried as decimal strings.

### 3.2 Hashing (HASH)

- **HASH-1** — BLAKE3 **MUST** be the internal default digest; SHA-256 **MUST** be available for interop. Both
  **MUST** appear in the corpus.
- **HASH-2** — A digest **MUST** be computed over the JCS bytes (CANON-1) with a domain/version prefix.

### 3.3 Content identifiers (CID)

- **CID-1** — Content identifiers **MUST** be CIDv1.

### 3.4 Signatures (SIG)

- **SIG-1** — Ed25519 verification **MUST** use `verify_strict` (rejecting non-canonical / small-order inputs).
- **SIG-2** — The DSSE Pre-Authentication Encoding **MUST** be `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`,
  where `SP` is `0x20`, `LEN` is ASCII decimal with no leading zeros, `type` is `"application/vnd.in-toto+json"`,
  and `body` is the **raw JCS bytes** of the Statement (never base64). The signature is over these PAE bytes.
- **SIG-3** — DSSE envelope verification **MUST** reject a `payloadType` other than `"application/vnd.in-toto+json"`
  and **MUST** require at least one signature to verify; the `payload` is read as standard **or** url-safe base64.
- **SIG-4** — A `did:key` **MUST** decode offline: multibase `z`/base58btc, Ed25519 multicodec `0xed 0x01`, exactly
  32 on-curve key bytes. A malformed, short, or off-curve key **MUST** fail closed (`SIG_MALFORMED_KEY`).
- **SIG-5** — A sealed turn **MUST** carry exactly one DSSE signature (ADR-0007).

### 3.5 Transparency log (LOG) — *Phase 2*

- **LOG-1** — Merkle tree hashing **MUST** follow RFC 6962 leaf/node domain separation: `hash_leaf = SHA-256(0x00 ‖
  leaf)`, `hash_children = SHA-256(0x01 ‖ left ‖ right)`, `empty_root = SHA-256("")`. The tree is **always**
  SHA-256 and carries no algorithm tag (distinct from a content `Digest`).
- **LOG-2** — `merkle_tree_hash` **MUST** split at the largest power of two strictly less than `n`
  (`k = 1 << (BITS-1 - (n-1).leading_zeros())`), and inclusion proofs **MUST** verify per RFC 9162 §2.1.3.1 with an
  exact path-length check (rejecting both too-long and too-short proofs).
- **LOG-3** — Consistency proofs **MUST** verify per RFC 9162 §2.1.4.2 by recomputing **both** the old and the new
  root and comparing each.
- **LOG-4** — A checkpoint **MUST** be a C2SP signed note: the signature line is prefixed by an em-dash and a space
  (U+2014, `0x20`), the key-hash is `SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ pubkey32)[..4]`, and verification **MUST**
  require at least one signature line to match a known key (unknown lines are ignored).
- **LOG-5** — Public-log tiles **MUST** follow the C2SP `tlog-tiles` layout (height-8 / 256-hash tiles; the
  `x`-prefixed three-digit-group index encoding).

### 3.6 Reasoning-trail schema (SCHEMA) — *Phase 2*

- **SCHEMA-1** — Every wire struct **MUST** canonicalize float-free with `deny_unknown_fields`: each `Digest` is the
  object `{"alg","bytes_hex"}`, every time is a decimal string, fixed-point params are integers (`*_milli`), and a
  salted commitment **MUST NOT** carry its salt on-ledger (no `salt_hex`).
- **SCHEMA-2** — `turn_id` **MUST** equal `hash_domain(BLAKE3, "thoughtmark.turn", canonicalize(turn))`; the
  manifest id **MUST** use the `"thoughtmark.manifest"` domain.
- **SCHEMA-3** — `trail_root` **MUST** be the dual `{"blake3","sha256"}` lowercase-hex map of
  `hash_domain(alg, "thoughtmark.object", canonicalize(trail))`.
- **SCHEMA-4** — An in-toto Statement **MUST** carry `_type = "https://in-toto.io/Statement/v1"`,
  `predicateType = "https://thoughtmark.dev/Provenance/v1"`, and `subject[].name = "trail:<trail_id>@<tree_size>"`
  with a dual `{blake3,sha256}` digest map.
- **SCHEMA-5** — `canon_version = "tm-jcs-1"` **MUST** be bound inside every preimage; an unknown canon version
  **MUST** fail closed (`UNKNOWN_CANON_VERSION`), never best-effort recompute.

### 3.7 Bundle (BUNDLE) — *Phase 2*

- **BUNDLE-1** — A `ThoughtmarkBundle` **MUST** carry `media_type = "application/vnd.thoughtmark.bundle.v1+json"`
  and a `u16` `bundle_version`; an unsupported version **MUST** fail closed (`BUNDLE_VERSION_UNSUPPORTED`) and a
  malformed shape **MUST** fail closed (`BUNDLE_SCHEMA_INVALID`). A bundle **MAY** staple the canonical bytes of the
  `Turn`/`RunManifest` bodies its predicate `Trail` references (`turn_bodies`/`run_manifests`), so `verify()` can
  replay the contribution-lineage DAG offline; an absent list canonicalizes identically to its omission.

### 3.8 Offline verification (VERIFY, POLICY) — *Phase 3*

- **VERIFY-1** — `verify(bundle, policy, clock, anchors)` **MUST** read the clock **exactly once** and run the nine
  checks in the fixed order `BundleSchema → CanonVersion → DsseSignature → StatementBinding → MerkleInclusion →
  Checkpoint → Consistency → AnchorReceipt → ContributionLineage`. For a well-formed run it **MUST** return a
  `VerificationResult` **value, never an error** (a tamper is a successful run with `total = false`); `total` is the
  AND of all non-`Skipped` checks. The result **MUST** always carry the constant `NotEstablished` honesty frame
  (I7). Malformed INPUT (bad JSON, bundle shape, or key) **MUST** instead return the error envelope
  (`BUNDLE_SCHEMA_INVALID` / `SIG_MALFORMED_KEY`). The JCS-canonical `VerificationResult` bytes **MUST** be
  byte-identical across Rust/WASM/TS.
- **VERIFY-2** — Each check **MUST** be independent: a single failure **MUST NOT** mask another. A tampered
  signature therefore yields `total = false` with `DsseSignature` failed yet `StatementBinding` / `MerkleInclusion`
  / `Checkpoint` / `ContributionLineage` still evaluated on the intact record; `unaltered_since_capture` **MUST**
  equal the AND of those four checks.
- **POLICY-1** — The `Policy` assertions **MUST** be enforced fail-closed: `require_anchor` requires ≥1 valid
  anchor (so it fails when none is present — no `AnchorVerifier` ships before Phase 4, hence `existed_at_or_before`
  stays absent); every `required_actions` entry **MUST** appear in the contribution ledger (else
  `POLICY_UNSATISFIED`); `accepted_canon_versions` rejects an unaccepted version (`UNKNOWN_CANON_VERSION`); and the
  checkpoint **MUST** carry ≥ `max(1, required_witnesses)` valid trusted-log-key cosignatures (counted over
  **distinct** keys).
- **VERIFY-3** — Each check **MUST** fail with its specific stable code when its precondition is violated:
  `BundleSchema` → `BUNDLE_SCHEMA_INVALID` / `BUNDLE_VERSION_UNSUPPORTED`; `CanonVersion` → `UNKNOWN_CANON_VERSION`;
  `StatementBinding` → `STATEMENT_SUBJECT_MISMATCH` when the recomputed dual `trail_root` ≠ `subject.digest`, the
  bound `tree_size` ≠ the inclusion proof's, the `subject` set is not a singleton, or a policy
  `expected_subject_digest` does not match; `MerkleInclusion` → `MERKLE_PROOF_INVALID` when the statement leaf is
  not under the checkpoint root **or** the signed checkpoint `size` ≠ the proof `tree_size`; `Checkpoint` →
  `CHECKPOINT_SIGNATURE_INVALID` for an untrusted/insufficient cosignature set or a `log_origin` mismatch. The
  `ContributionLineage` DAG **MUST** be well-formed — every stapled turn body recomputes to a declared `turn_id`,
  every declared turn is stapled (a body-less declared turn fails; lineage is mandatory), no duplicate turn id,
  every `parents`/`supersedes` target resolves, the parent graph is acyclic, each ledger `attested_at` is
  non-decreasing along every parent edge, and every `run_manifest_ref` is matched by a stapled manifest — any
  violation fails with `LEDGER_BROKEN_LINK` / `LEDGER_NON_MONOTONIC_TIME`.

## 4. The error envelope

On failure, an operation **MUST** return exactly these bytes (UTF-8, no trailing newline, members in the order
shown), where `<CODE>` is a stable SCREAMING_SNAKE_CASE `ErrorCode`:

```
{"ok":false,"error":{"code":"<CODE>"}}
```

The Tier-0 codes are `CANON_INVALID_JSON`, `CANON_NON_DETERMINISTIC_FLOAT`, `CANON_INTEGER_OUT_OF_RANGE`,
`UNKNOWN_CANON_VERSION`, `UNKNOWN_HASH_ALG`, `DIGEST_MISMATCH`, `CID_MALFORMED`, and `INTERNAL` (the catch-all for
an internal invariant; it never carries record or secret data).

The Tier-1 codes (Phase 2), appended in order, are `SIG_INVALID`, `SIG_MALFORMED_KEY`, `DSSE_BAD_ENVELOPE`,
`DSSE_PAYLOAD_TYPE_MISMATCH`, `STATEMENT_SUBJECT_MISMATCH`, `PREDICATE_SCHEMA_INVALID`, `MERKLE_PROOF_INVALID`,
`MERKLE_INDEX_OUT_OF_RANGE`, `CONSISTENCY_PROOF_INVALID`, `CHECKPOINT_SIGNATURE_INVALID`,
`ANCHOR_RECEIPT_MALFORMED`, `ANCHOR_ROOT_MISMATCH`, `ANCHOR_TIME_IMPLAUSIBLE`, `ANCHOR_UNSUPPORTED_KIND`,
`LEDGER_BROKEN_LINK`, `LEDGER_NON_MONOTONIC_TIME`, `REDACT_TARGET_NOT_FOUND`, `BUNDLE_SCHEMA_INVALID`,
`BUNDLE_VERSION_UNSUPPORTED`, and `POLICY_UNSATISFIED`.

Codes are **append-only**; each token is normative and appears in the negative `spec/vectors/` cases. Negative
vectors assert that both engines return the same code, fail-closed (CORE-2).

[RFC 2119]: https://www.rfc-editor.org/info/rfc2119
[RFC 8174]: https://www.rfc-editor.org/info/rfc8174
