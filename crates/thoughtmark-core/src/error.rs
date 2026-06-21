// SPDX-License-Identifier: Apache-2.0
//! The crate-wide flat error model (arch §10.2).
//!
//! One [`ErrorCode`] (the stable, serializable wire token) and one [`Error`] (a content-free, `#[non_exhaustive]`
//! enum whose `Display` strings are constant — no record bytes, no secret material, no oracle for an attacker).
//! "Impossible" cases return [`Error::Internal`] carrying a `'static` site tag rather than panicking, because a
//! Rust panic crossing the WASM boundary becomes an uncatchable `RuntimeError` (arch §2.3).
//!
//! Codes are **append-only**: the SCREAMING_SNAKE_CASE wire token of each is normative (it appears in the
//! conformance envelope and in negative vectors), so renaming or repurposing one is a breaking spec change.

use crate::canon::error::CanonError;

/// A stable, content-free, serializable error code.
///
/// `#[non_exhaustive]` and append-only. Serialized as SCREAMING_SNAKE_CASE (e.g. `CANON_NON_DETERMINISTIC_FLOAT`);
/// [`ErrorCode::as_str`] returns the identical token without invoking serde so the envelope stays alloc/panic
/// clean (a unit test pins `as_str` == the serde token). Tier-1 codes are appended as their tiers land.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Input was not well-formed I-JSON (syntax, non-UTF-8, or a duplicate object key).
    CanonInvalidJson,
    /// A JSON number was a float / had an exponent — forbidden on the hashed path (I4).
    CanonNonDeterministicFloat,
    /// A JSON integer fell outside the I-JSON safe range `[-(2^53 - 1), 2^53 - 1]`.
    CanonIntegerOutOfRange,
    /// A canonicalization-version tag was not understood by this build; fail closed.
    UnknownCanonVersion,
    /// A hash-algorithm token was not `"blake3"` or `"sha256"`.
    UnknownHashAlg,
    /// A recomputed digest did not match an expected digest.
    DigestMismatch,
    /// A CID was malformed, or a parsed CID failed the pinned-length check.
    CidMalformed,
    /// A Merkle inclusion proof did not reconstruct the expected root, or was structurally malformed (e.g. a
    /// path of the wrong length — the proof-padding forgery vector).
    MerkleProofInvalid,
    /// A leaf index was out of range for the stated tree size.
    MerkleIndexOutOfRange,
    /// A Merkle consistency proof did not reconcile the old and new roots.
    ConsistencyProofInvalid,
    /// An Ed25519 signature failed `verify_strict` (bad signature, non-canonical `S`, or small-order input).
    SigInvalid,
    /// A public key / `did:key` was malformed, the wrong length, or off-curve.
    SigMalformedKey,
    /// A DSSE envelope was structurally malformed (bad base64, missing fields, no signatures).
    DsseBadEnvelope,
    /// A DSSE envelope's `payloadType` was not `application/vnd.in-toto+json`.
    DssePayloadTypeMismatch,
    /// A checkpoint (signed note) carried no signature line that matched a known key (or was malformed).
    CheckpointSignatureInvalid,
    /// An anchor receipt was structurally malformed.
    AnchorReceiptMalformed,
    /// An anchor receipt's root did not match the checkpoint it claims to anchor.
    AnchorRootMismatch,
    /// An anchor's asserted time was implausible.
    AnchorTimeImplausible,
    /// An anchor receipt named a kind this build does not support.
    AnchorUnsupportedKind,
    /// A `ThoughtmarkBundle` was structurally malformed (bad media type / canon version / shape).
    BundleSchemaInvalid,
    /// A `ThoughtmarkBundle` declared a `bundle_version` this build does not support.
    BundleVersionUnsupported,
    /// The in-toto subject did not bind the trail (digest / name / tree_size mismatch) — `verify` (§11).
    StatementSubjectMismatch,
    /// The signed predicate was not a well-formed `Provenance/v1` Trail — `verify` (§11).
    PredicateSchemaInvalid,
    /// The contribution lineage DAG was broken: a cycle, a dangling parent, a missing `supersedes` target, or a
    /// `run_manifest_ref` with no matching manifest — `verify` (§11).
    LedgerBrokenLink,
    /// A ledger `attested_at` decreased along the lineage chain (non-monotonic time) — `verify` (§11).
    LedgerNonMonotonicTime,
    /// A redaction target was not found (reserved for Phase 5 `redact`; present so the frozen `ErrorCode` set
    /// equals the SPEC §4 enumeration).
    RedactTargetNotFound,
    /// The caller's `Policy` was not satisfied (a required action / witness / anchor threshold) — `verify` (§11).
    PolicyUnsatisfied,
    /// An internal invariant was violated (a static, content-free site tag, never runtime/secret data).
    Internal,
}

impl ErrorCode {
    /// The stable wire token for this code — byte-identical to its serde SCREAMING_SNAKE_CASE form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::CanonInvalidJson => "CANON_INVALID_JSON",
            ErrorCode::CanonNonDeterministicFloat => "CANON_NON_DETERMINISTIC_FLOAT",
            ErrorCode::CanonIntegerOutOfRange => "CANON_INTEGER_OUT_OF_RANGE",
            ErrorCode::UnknownCanonVersion => "UNKNOWN_CANON_VERSION",
            ErrorCode::UnknownHashAlg => "UNKNOWN_HASH_ALG",
            ErrorCode::DigestMismatch => "DIGEST_MISMATCH",
            ErrorCode::CidMalformed => "CID_MALFORMED",
            ErrorCode::MerkleProofInvalid => "MERKLE_PROOF_INVALID",
            ErrorCode::MerkleIndexOutOfRange => "MERKLE_INDEX_OUT_OF_RANGE",
            ErrorCode::ConsistencyProofInvalid => "CONSISTENCY_PROOF_INVALID",
            ErrorCode::SigInvalid => "SIG_INVALID",
            ErrorCode::SigMalformedKey => "SIG_MALFORMED_KEY",
            ErrorCode::DsseBadEnvelope => "DSSE_BAD_ENVELOPE",
            ErrorCode::DssePayloadTypeMismatch => "DSSE_PAYLOAD_TYPE_MISMATCH",
            ErrorCode::CheckpointSignatureInvalid => "CHECKPOINT_SIGNATURE_INVALID",
            ErrorCode::AnchorReceiptMalformed => "ANCHOR_RECEIPT_MALFORMED",
            ErrorCode::AnchorRootMismatch => "ANCHOR_ROOT_MISMATCH",
            ErrorCode::AnchorTimeImplausible => "ANCHOR_TIME_IMPLAUSIBLE",
            ErrorCode::AnchorUnsupportedKind => "ANCHOR_UNSUPPORTED_KIND",
            ErrorCode::BundleSchemaInvalid => "BUNDLE_SCHEMA_INVALID",
            ErrorCode::BundleVersionUnsupported => "BUNDLE_VERSION_UNSUPPORTED",
            ErrorCode::StatementSubjectMismatch => "STATEMENT_SUBJECT_MISMATCH",
            ErrorCode::PredicateSchemaInvalid => "PREDICATE_SCHEMA_INVALID",
            ErrorCode::LedgerBrokenLink => "LEDGER_BROKEN_LINK",
            ErrorCode::LedgerNonMonotonicTime => "LEDGER_NON_MONOTONIC_TIME",
            ErrorCode::RedactTargetNotFound => "REDACT_TARGET_NOT_FOUND",
            ErrorCode::PolicyUnsatisfied => "POLICY_UNSATISFIED",
            ErrorCode::Internal => "INTERNAL",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The library error type. Content-free by construction (I5/I7); `Display` is a constant per variant.
///
/// `#[non_exhaustive]` and append-only. Crypto/canon failures collapse to a single `Display` string,
/// distinguishable only by [`Error::code`] — no error message ever discriminates *why* a verification failed.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Canonicalization, no-float, hash-alg, or version failure (the carried code says which).
    #[error("canonicalization failed")]
    Canon(ErrorCode),
    /// A digest comparison failed.
    #[error("digest mismatch")]
    Digest(ErrorCode),
    /// A CID was malformed.
    #[error("cid malformed")]
    Cid(ErrorCode),
    /// A Merkle inclusion proof failed to verify (the carried code says how).
    #[error("merkle inclusion proof invalid")]
    Inclusion(ErrorCode),
    /// A Merkle consistency proof failed to verify.
    #[error("merkle consistency proof invalid")]
    Consistency(ErrorCode),
    /// An Ed25519 signature or key failed (the carried code says which).
    #[error("signature verification failed")]
    Signature(ErrorCode),
    /// A DSSE envelope was invalid.
    #[error("DSSE envelope invalid")]
    Dsse(ErrorCode),
    /// A statement binding failed (subject mismatch or malformed predicate) — `verify` (§11).
    #[error("statement binding invalid")]
    Statement(ErrorCode),
    /// A contribution-lineage check failed (broken link, non-monotonic time, or policy unsatisfied) — `verify`.
    #[error("contribution lineage invalid")]
    Lineage(ErrorCode),
    /// An anchor receipt was invalid.
    #[error("anchor receipt invalid")]
    Anchor(ErrorCode),
    /// A bundle was structurally invalid.
    #[error("bundle invalid")]
    Bundle(ErrorCode),
    /// An internal invariant was violated; the `'static` tag is a code site, never runtime/secret data.
    #[error("internal invariant violated")]
    Internal(&'static str),
}

impl Error {
    /// The stable [`ErrorCode`] for this error (the token that reaches the wire).
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Error::Canon(c)
            | Error::Digest(c)
            | Error::Cid(c)
            | Error::Inclusion(c)
            | Error::Consistency(c)
            | Error::Signature(c)
            | Error::Dsse(c)
            | Error::Statement(c)
            | Error::Lineage(c)
            | Error::Anchor(c)
            | Error::Bundle(c) => *c,
            Error::Internal(_) => ErrorCode::Internal,
        }
    }

    /// The constant, content-free message for this error.
    #[must_use]
    pub const fn static_message(&self) -> &'static str {
        match self {
            Error::Canon(_) => "canonicalization failed",
            Error::Digest(_) => "digest mismatch",
            Error::Cid(_) => "cid malformed",
            Error::Inclusion(_) => "merkle inclusion proof invalid",
            Error::Consistency(_) => "merkle consistency proof invalid",
            Error::Signature(_) => "signature verification failed",
            Error::Dsse(_) => "DSSE envelope invalid",
            Error::Statement(_) => "statement binding invalid",
            Error::Lineage(_) => "contribution lineage invalid",
            Error::Anchor(_) => "anchor receipt invalid",
            Error::Bundle(_) => "bundle invalid",
            Error::Internal(tag) => tag,
        }
    }

    /// Shorthand for an internal-invariant error carrying a `'static` site tag.
    #[must_use]
    pub const fn internal(tag: &'static str) -> Self {
        Error::Internal(tag)
    }
}

/// The crate result alias.
pub type Result<T> = core::result::Result<T, Error>;

impl From<CanonError> for ErrorCode {
    fn from(e: CanonError) -> Self {
        match e {
            CanonError::InvalidJson | CanonError::DuplicateKey => ErrorCode::CanonInvalidJson,
            CanonError::FloatNotAllowed => ErrorCode::CanonNonDeterministicFloat,
            CanonError::IntegerOutOfRange => ErrorCode::CanonIntegerOutOfRange,
            CanonError::UnknownCanonVersion => ErrorCode::UnknownCanonVersion,
            CanonError::UnknownHashAlg => ErrorCode::UnknownHashAlg,
            CanonError::Cid | CanonError::Multihash => ErrorCode::CidMalformed,
        }
    }
}

impl From<CanonError> for Error {
    fn from(e: CanonError) -> Self {
        let code = ErrorCode::from(e);
        match e {
            CanonError::Cid | CanonError::Multihash => Error::Cid(code),
            _ => Error::Canon(code),
        }
    }
}
