// SPDX-License-Identifier: Apache-2.0
//! RFC 6962 leaf/node hashing and the [`TreeHash`] newtype (arch §6.1, ADR-0013).
//!
//! The transparency tree is **always SHA-256** and a [`TreeHash`] carries no algorithm tag — it is a distinct type
//! from the Tier-0 content [`crate::Digest`], so "I forgot to leaf-hash" or "I mixed a content digest into the
//! tree" is a *type* error. The `0x00`/`0x01` prefixes are the ONLY domain separation in the tree (never the §4.5
//! ASCII-string scheme). [`TreeHash`] serializes as a STANDARD-padded base64 string (matching the checkpoint body
//! and tlog-tiles encodings); it accepts standard or url-safe on read and fails closed if not exactly 32 bytes.

use crate::base64;
use crate::canon::digest::sha256_array;
use alloc::vec::Vec;
use subtle::ConstantTimeEq as _;

/// The RFC 6962 leaf prefix: `hash_leaf = SHA-256(0x00 || leaf)`.
pub const LEAF_PREFIX: u8 = 0x00;
/// The RFC 6962 node prefix: `hash_children = SHA-256(0x01 || left || right)`.
pub const NODE_PREFIX: u8 = 0x01;

/// A SHA-256 transparency-tree node hash. Always SHA-256; no algorithm tag (ADR-0013).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TreeHash([u8; 32]);

impl TreeHash {
    /// Wrap 32 raw bytes as a [`TreeHash`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        TreeHash(bytes)
    }

    /// The raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality — never a short-circuiting `==` on hash bytes (timing-oracle hygiene).
    #[must_use]
    pub fn ct_eq(&self, other: &TreeHash) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

/// Debug prints the base64 form, never the raw array (keeps logs content-light, like `Digest`).
impl core::fmt::Debug for TreeHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TreeHash(")?;
        f.write_str(&base64::encode_std(&self.0))?;
        f.write_str(")")
    }
}

impl serde::Serialize for TreeHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::encode_std(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for TreeHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Fail-closed: a non-base64 string, or one that is not exactly 32 bytes, carries MERKLE_PROOF_INVALID.
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        let code = crate::error::ErrorCode::MerkleProofInvalid.as_str();
        let bytes = base64::decode_any(s).ok_or_else(|| serde::de::Error::custom(code))?;
        let arr =
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| serde::de::Error::custom(code))?;
        Ok(TreeHash(arr))
    }
}

/// `hash_leaf(leaf) = SHA-256(0x00 || leaf)` (RFC 6962 §2.1).
#[must_use]
pub fn hash_leaf(leaf: &[u8]) -> TreeHash {
    let mut preimage = Vec::with_capacity(leaf.len().saturating_add(1));
    preimage.push(LEAF_PREFIX);
    preimage.extend_from_slice(leaf);
    TreeHash(sha256_array(&preimage))
}

/// `hash_children(l, r) = SHA-256(0x01 || l || r)` (RFC 6962 §2.1).
#[must_use]
pub fn hash_children(left: &TreeHash, right: &TreeHash) -> TreeHash {
    let mut preimage = Vec::with_capacity(65);
    preimage.push(NODE_PREFIX);
    preimage.extend_from_slice(&left.0);
    preimage.extend_from_slice(&right.0);
    TreeHash(sha256_array(&preimage))
}

/// `empty_root() = SHA-256("")` — the Merkle tree hash of an empty log (RFC 6962 §2.1).
#[must_use]
pub fn empty_root() -> TreeHash {
    TreeHash(sha256_array(&[]))
}
