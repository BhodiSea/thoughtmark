// SPDX-License-Identifier: Apache-2.0
//! Domain separation and the canonicalization version (arch §4.5).
//!
//! [`CANON_VERSION`] is the format identifier bound INTO every content-hash preimage (one value everywhere,
//! ADR-0001), so an artifact stays verifiable forever: a verifier dispatches on the embedded version and an
//! unknown one fails closed. The three content-hash domains are the only structured-JSON objects that get a
//! self-identifying id; everything else is a salted content digest of raw bytes (`salt.rs`), and the transparency
//! log uses RFC 6962 leaf/node hashing (deliberately distinct).

use crate::canon::digest::{Digest, HashAlg, hash_with};
use alloc::vec::Vec;

/// The canonicalization format identifier, bound into every content-hash preimage.
pub const CANON_VERSION: &str = "tm-jcs-1";

/// Domain for hashing a canonical object (e.g. a `Trail` root).
pub const OBJECT: &str = "thoughtmark.object";
/// Domain for hashing a canonical `Turn`.
pub const TURN: &str = "thoughtmark.turn";
/// Domain for hashing a canonical run manifest.
pub const MANIFEST: &str = "thoughtmark.manifest";

/// Build the preimage prefix `CANON_VERSION ":" alg ":" domain ":"`, e.g.
/// `b"tm-jcs-1:blake3:thoughtmark.turn:"`.
#[must_use]
pub fn prefix(alg: HashAlg, domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(CANON_VERSION.as_bytes());
    out.push(b':');
    out.extend_from_slice(alg.as_str().as_bytes());
    out.push(b':');
    out.extend_from_slice(domain.as_bytes());
    out.push(b':');
    out
}

/// The core domain-separated content hash: `H(prefix(alg, domain) || canonical_json)`.
#[must_use]
pub fn hash_domain(alg: HashAlg, domain: &str, canonical_json: &[u8]) -> Digest {
    let mut preimage = prefix(alg, domain);
    preimage.extend_from_slice(canonical_json);
    hash_with(alg, &preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_exact() {
        assert_eq!(
            prefix(HashAlg::Blake3, TURN),
            b"tm-jcs-1:blake3:thoughtmark.turn:"
        );
        assert_eq!(
            prefix(HashAlg::Sha256, OBJECT),
            b"tm-jcs-1:sha256:thoughtmark.object:"
        );
    }

    #[test]
    fn hash_domain_binds_prefix() {
        let canon = b"{\"a\":1}";
        let bound = hash_domain(HashAlg::Blake3, TURN, canon);
        // Distinct from the raw hash of the same canonical bytes — the prefix is really mixed in.
        assert_ne!(bound.bytes, hash_with(HashAlg::Blake3, canon).bytes);
    }
}
