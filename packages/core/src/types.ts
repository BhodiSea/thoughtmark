// SPDX-License-Identifier: Apache-2.0
/**
 * The frozen `@thoughtmark/core` type surface (arch §14.6).
 *
 * One-to-one with the Rust verbs. `u64`/`i64` are `bigint` everywhere (never `number`, I4); digests/proofs are
 * `Uint8Array`; version/alg selectors are string-literal unions; the {@link ErrorCode} union is **exactly equal**
 * to the Rust `ErrorCode` set (§10.2). These are the wire-mirroring types the typed facade returns after the
 * `run_op` byte-airlock (§12.1) — the byte-identity guarantee is enforced at the `runOp` corpus level.
 */

/** The canonicalization format identifier (frozen value, §14.2). */
export type CanonVersion = "tm-jcs-1";

/** A content-hash algorithm (§4.4). */
export type HashAlg = "blake3" | "sha256";

/** A 32-byte content digest tagged with its algorithm. Raw bytes — hex/base64 live in a codec, never here. */
export interface Digest {
  alg: HashAlg;
  bytes: Uint8Array;
}

/** A 32-byte SHA-256 transparency-tree node hash (distinct from a content {@link Digest}). */
export type TreeHash = Uint8Array;

/**
 * The stable error codes, **exactly equal to the Rust `ErrorCode` set** (the cross-language equality gate). A
 * failed operation throws a `ThoughtmarkError` carrying one of these; a `verify` tamper is NOT an error (it is a
 * value with `total:false`).
 */
export type ErrorCode =
  | "CANON_INVALID_JSON"
  | "CANON_NON_DETERMINISTIC_FLOAT"
  | "CANON_INTEGER_OUT_OF_RANGE"
  | "UNKNOWN_CANON_VERSION"
  | "UNKNOWN_HASH_ALG"
  | "DIGEST_MISMATCH"
  | "CID_MALFORMED"
  | "MERKLE_PROOF_INVALID"
  | "MERKLE_INDEX_OUT_OF_RANGE"
  | "CONSISTENCY_PROOF_INVALID"
  | "SIG_INVALID"
  | "SIG_MALFORMED_KEY"
  | "DSSE_BAD_ENVELOPE"
  | "DSSE_PAYLOAD_TYPE_MISMATCH"
  | "CHECKPOINT_SIGNATURE_INVALID"
  | "ANCHOR_RECEIPT_MALFORMED"
  | "ANCHOR_ROOT_MISMATCH"
  | "ANCHOR_TIME_IMPLAUSIBLE"
  | "ANCHOR_UNSUPPORTED_KIND"
  | "BUNDLE_SCHEMA_INVALID"
  | "BUNDLE_VERSION_UNSUPPORTED"
  | "STATEMENT_SUBJECT_MISMATCH"
  | "PREDICATE_SCHEMA_INVALID"
  | "LEDGER_BROKEN_LINK"
  | "LEDGER_NON_MONOTONIC_TIME"
  | "REDACT_TARGET_NOT_FOUND"
  | "POLICY_UNSATISFIED"
  | "INTERNAL";

/** The status of a single verify check. */
export type CheckStatus = "Pass" | "Fail" | "Skipped";

/** The kinds of verify check, in fixed order (§11.2). */
export type CheckKind =
  | "BundleSchema"
  | "CanonVersion"
  | "DsseSignature"
  | "StatementBinding"
  | "MerkleInclusion"
  | "Checkpoint"
  | "Consistency"
  | "AnchorReceipt"
  | "ContributionLineage";

/** Non-sensitive scalar context for a check outcome (counts / sizes only — never record bytes). */
export interface CheckDetail {
  matched?: number;
  required?: number;
  /** A tree size (`u64` → `bigint`). */
  treeSize?: bigint;
}

/** The outcome of one verify check (§11.3). */
export interface CheckOutcome {
  kind: CheckKind;
  status: CheckStatus;
  code?: ErrorCode;
  detail?: CheckDetail;
}

/** One step in the contribution lineage (§11.3). */
export interface LineageStep {
  participantKind: "human" | "ai";
  participantId: string;
  action: string;
  /** The injected attestation time (`UnixMillis` → `bigint`). */
  at: bigint;
}

/** The affirmative claims a passing verification establishes (§11.3). */
export interface Established {
  /** The tightest UPPER time bound (min over passing anchors); `undefined` at 1.0 (no anchor verifier ships). */
  existedAtOrBefore?: bigint;
  unalteredSinceCapture: boolean;
  lineage?: LineageStep[];
  boundSubjectDigest?: Digest;
  signedBy: string[];
  logOrigin?: string;
}

/** The permanent non-claims — the integrity-of-record honesty frame (I7), constant in v1. */
export interface NotEstablished {
  validityOfRecord: string;
  faithfulness: string;
  authorshipTruth: string;
  completeness: string;
  timeUpperBoundOnly: string;
}

/** The full verification verdict + report (§11.3). A tamper is a value with `total:false`, never a throw. */
export interface VerificationResult {
  schema: string;
  /** The injected `now` (`UnixMillis` → `bigint`). */
  verifiedAt: bigint;
  total: boolean;
  checks: CheckOutcome[];
  established: Established;
  notEstablished: NotEstablished;
}

/** The caller's verification policy (the op-input form; keys as `did:key`/hex strings, §11.1). */
export interface Policy {
  expectedSubjectDigest?: { alg: HashAlg; bytesHex: string };
  trustedKeys?: string[];
  logOrigin?: string;
  trustedLogKeys?: string[];
  requiredWitnesses: number;
  requireAnchor: boolean;
  /** Tolerated clock skew (`i64` → `bigint`). */
  maxClockSkewMs: bigint;
  requiredActions?: string[];
  acceptedCanonVersions: CanonVersion[];
}

/** Names of operations dispatched through the `run_op` byte-airlock seam. */
export type OpName =
  | "canonicalize"
  | "hash_blake3"
  | "hash_sha256"
  | "cid_v1"
  | "hash_domain_turn"
  | "hash_domain_object"
  | "hash_domain_manifest"
  | "trail_root"
  | "merkle_root"
  | "inclusion_proof"
  | "consistency_proof"
  | "merkle_verify_inclusion"
  | "merkle_verify_consistency"
  | "dsse_pae"
  | "ed25519_verify"
  | "did_key_decode"
  | "dsse_verify_envelope"
  | "sign_statement"
  | "checkpoint_body"
  | "checkpoint_verify"
  | "bundle_check"
  | "verify";
