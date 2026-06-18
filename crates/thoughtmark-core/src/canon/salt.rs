// SPDX-License-Identifier: Apache-2.0
//! Salted content commitments (arch §4.7, ADR-0012, I5).
//!
//! The salt is supplied by the caller's INJECTED RNG — core never calls `rand` (I3). The salt is **off-ledger by
//! construction**: it is NOT part of the digest's serialization and NEVER enters a canonical `Turn` or signed
//! `Statement`. That is the redaction / crypto-shredding foundation and the reason on-ledger content carries
//! `digest_hex` only, never `salt_hex` — a salt committed inside signed/logged bytes could never be deleted.
//! [`Salt`] is therefore deliberately not `Serialize`/`Debug`, and is zeroized on drop.

use crate::canon::digest::{Digest, HashAlg, hash_with};
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte salt for a content commitment. Secret material: not serializable, not `Debug`, wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Salt(pub [u8; 32]);

/// The salted content commitment: `H(salt || content)` over **raw** bytes (NOT JCS, NOT domain-prefixed). The
/// salt-bearing preimage is wiped from memory before returning.
#[must_use]
pub fn salted_content_digest(alg: HashAlg, salt: &Salt, content: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(content.len().saturating_add(32));
    preimage.extend_from_slice(&salt.0);
    preimage.extend_from_slice(content);
    let digest = hash_with(alg, &preimage);
    preimage.zeroize();
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_changes_the_digest() {
        let content = b"hello";
        let a = salted_content_digest(HashAlg::Blake3, &Salt([0u8; 32]), content);
        let b = salted_content_digest(HashAlg::Blake3, &Salt([1u8; 32]), content);
        assert_ne!(a.bytes, b.bytes);
        // raw hash of salt||content, recomputed independently
        let mut pre = Vec::new();
        pre.extend_from_slice(&[0u8; 32]);
        pre.extend_from_slice(content);
        assert_eq!(a.bytes, hash_with(HashAlg::Blake3, &pre).bytes);
    }
}
