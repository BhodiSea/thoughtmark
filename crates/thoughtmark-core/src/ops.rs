// SPDX-License-Identifier: Apache-2.0
//! Tier-0 / Tier-1 operations.
//!
//! Every operation here is a Phase-0 **stub** returning [`Error::not_implemented`]. [`run_op`] is the
//! string-dispatched entry point shared by the native conformance runner and the WASM binding: it maps any
//! result (today, always not-implemented) to the canonical envelope bytes, so the cross-language byte-identity
//! gate (CORE-1/CORE-2) is exercised before real logic lands in Phase 1.

use crate::envelope::error_envelope;
use crate::error::Error;
use alloc::vec::Vec;

/// Canonicalize a JSON document to RFC 8785 (JCS) bytes (CANON-1). **Stub.**
///
/// # Errors
/// Returns [`crate::ErrorCode::NotImplemented`] until Phase 1.
pub fn canonicalize(_input: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::not_implemented())
}

/// Compute the BLAKE3 digest of JCS bytes (HASH-1/HASH-2). **Stub.**
///
/// # Errors
/// Returns [`crate::ErrorCode::NotImplemented`] until Phase 1.
pub fn hash_blake3(_input: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::not_implemented())
}

/// Compute the SHA-256 digest of JCS bytes (HASH-1/HASH-2). **Stub.**
///
/// # Errors
/// Returns [`crate::ErrorCode::NotImplemented`] until Phase 1.
pub fn hash_sha256(_input: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::not_implemented())
}

/// Compute the CIDv1 of content (CID-1). **Stub.**
///
/// # Errors
/// Returns [`crate::ErrorCode::NotImplemented`] until Phase 1.
pub fn cid_v1(_input: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::not_implemented())
}

/// Dispatch a named operation over raw input bytes and return its canonical output bytes.
///
/// In Phase 0 every known operation (and every unknown one) yields the canonical `NOT_IMPLEMENTED` envelope
/// (CORE-2), so this single entry point makes the conformance gate real against stubs.
#[must_use]
pub fn run_op(op: &str, input: &[u8]) -> Vec<u8> {
    let result = match op {
        "canonicalize" => canonicalize(input),
        "hash_blake3" => hash_blake3(input),
        "hash_sha256" => hash_sha256(input),
        "cid_v1" => cid_v1(input),
        _ => Err(Error::not_implemented()),
    };
    match result {
        Ok(bytes) => bytes,
        Err(err) => error_envelope(err.code),
    }
}
