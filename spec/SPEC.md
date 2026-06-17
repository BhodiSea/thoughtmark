# thoughtmark — Normative Specification

**Status:** Draft (Phase 0). No wire-format freeze yet (that lands at the end of Phase 2).
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

### 3.5 Transparency log (LOG) — *reserved, Phase 2*

- **LOG-1** — Merkle tree hashing **MUST** follow RFC 6962 leaf/node domain separation. *(No vectors until Phase 2.)*

## 4. The error envelope

On failure, an operation **MUST** return exactly these bytes (UTF-8, no trailing newline, members in the order
shown), where `<CODE>` is a stable SCREAMING_SNAKE_CASE `ErrorCode`:

```
{"ok":false,"error":{"code":"<CODE>"}}
```

The Tier-0 codes are `CANON_INVALID_JSON`, `CANON_NON_DETERMINISTIC_FLOAT`, `CANON_INTEGER_OUT_OF_RANGE`,
`UNKNOWN_CANON_VERSION`, `UNKNOWN_HASH_ALG`, `DIGEST_MISMATCH`, `CID_MALFORMED`, and `INTERNAL` (the catch-all for
an internal invariant; it never carries record or secret data). Codes are **append-only**; each token is normative
and appears in the negative `spec/vectors/` cases. Negative vectors assert that both engines return the same code,
fail-closed (CORE-2).

[RFC 2119]: https://www.rfc-editor.org/info/rfc2119
[RFC 8174]: https://www.rfc-editor.org/info/rfc8174
