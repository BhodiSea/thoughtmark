// SPDX-License-Identifier: Apache-2.0
//! The Tier-0 canonicalization error type.
//!
//! `CanonError` is the local error of the `canon` module. Its `Display` strings are constant and content-free
//! (I5/I7): a canonicalization failure never leaks the record bytes that triggered it. It maps into the crate-wide
//! [`crate::error::ErrorCode`] via `From` (arch §10.2), which is the token that appears on the wire.

/// A Tier-0 canonicalization / hashing / CID error.
///
/// `#[non_exhaustive]` — variants are append-only. Content-free by construction.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonError {
    /// The input was not well-formed I-JSON (syntax error, non-UTF-8, or a duplicate object key that the
    /// dedicated [`CanonError::DuplicateKey`] did not already classify).
    #[error("invalid json")]
    InvalidJson,
    /// A JSON number was a non-integer (a float, or had an exponent) — forbidden on the hashed path (I4).
    #[error("float not allowed")]
    FloatNotAllowed,
    /// A JSON integer fell outside the I-JSON safe range `[-(2^53 - 1), 2^53 - 1]`.
    #[error("integer out of range")]
    IntegerOutOfRange,
    /// An object contained the same key twice (I-JSON forbids duplicate keys).
    #[error("duplicate key")]
    DuplicateKey,
    /// A multihash could not be constructed (an internal invariant — the digest length is always 32 here).
    #[error("multihash error")]
    Multihash,
    /// A CID could not be parsed, or a parsed CID failed the pinned-length check.
    #[error("cid error")]
    Cid,
    /// A hash-algorithm token was not one of the known wire tokens (`"blake3"` / `"sha256"`).
    #[error("unknown hash alg")]
    UnknownHashAlg,
    /// A canonicalization-version tag was not the one this build understands (`"tm-jcs-1"`); fail closed.
    #[error("unknown canon version")]
    UnknownCanonVersion,
}
