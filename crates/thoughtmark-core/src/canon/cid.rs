// SPDX-License-Identifier: Apache-2.0
//! CIDv1 content identifiers for opaque binary blobs (arch §4.6).
//!
//! A CID addresses a raw blob that is NEVER inlined into canonical JSON. The multihash is taken over the **raw**
//! digest bytes (NOT JCS, NOT domain-prefixed). The canonical text form is pinned to base32-lower (multibase `b`)
//! — never `Cid::to_string()`'s default. BLAKE3's multihash code (`0x1e`) is variable-length, so the parse path
//! rejects any BLAKE3 CID whose multihash length ≠ 32 (two CIDs for one blob must not be possible).

use crate::canon::digest::{HashAlg, hash_with};
use crate::canon::error::CanonError;
use alloc::string::String;
use cid::Cid;
use multihash::Multihash;

/// The multicodec code for a raw (un-typed) blob.
pub const RAW_CODEC: u64 = 0x55;

/// The BLAKE3 multihash is pinned to exactly 32 bytes.
const BLAKE3_MULTIHASH_LEN: usize = 32;

/// Construct a CIDv1 (raw codec) over the raw digest of `blob`.
///
/// # Errors
/// Returns [`CanonError::Multihash`] if the (always-32-byte) digest cannot be wrapped — unreachable in practice.
pub fn cid_blob(alg: HashAlg, blob: &[u8]) -> Result<Cid, CanonError> {
    let digest = hash_with(alg, blob);
    let mh = Multihash::<64>::wrap(alg.multihash_code(), &digest.bytes)
        .map_err(|_| CanonError::Multihash)?;
    Ok(Cid::new_v1(RAW_CODEC, mh))
}

/// Render a CID as a base32-lower (multibase `b`) string — the pinned canonical text form.
///
/// # Errors
/// Returns [`CanonError::Cid`] if base32-lower encoding is unavailable — unreachable for a v1 CID.
pub fn cid_to_string(cid: &Cid) -> Result<String, CanonError> {
    cid.to_string_of_base(cid::multibase::Base::Base32Lower)
        .map_err(|_| CanonError::Cid)
}

/// Parse a CID string, rejecting any BLAKE3 (`0x1e`) CID whose multihash length ≠ 32 (the length-pinning rule
/// shared with [`crate::canon::digest::Digest::multihash_bytes`]).
///
/// # Errors
/// Returns [`CanonError::Cid`] on a malformed CID or a BLAKE3 multihash whose length is not 32.
pub fn cid_from_str(s: &str) -> Result<Cid, CanonError> {
    let cid: Cid = s.parse().map_err(|_| CanonError::Cid)?;
    let mh = cid.hash();
    if mh.code() == HashAlg::Blake3.multihash_code() && mh.size() as usize != BLAKE3_MULTIHASH_LEN {
        return Err(CanonError::Cid);
    }
    Ok(cid)
}
