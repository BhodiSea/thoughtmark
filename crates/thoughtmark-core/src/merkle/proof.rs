// SPDX-License-Identifier: Apache-2.0
//! Merkle proof types and construction (arch §6.3).
//!
//! [`InclusionProof`]/[`ConsistencyProof`] are the wire types; their `u64` index/size fields travel as decimal
//! strings (I4) and the audit-path hashes as base64 [`TreeHash`]es. Construction here is over a full leaf-hash
//! slice (what an in-memory log holds); the [`MerkleReader`] trait is the injected-node seam a storage-backed log
//! ([`thoughtmark-log`], a later phase) implements. The *verification* of these proofs is the audited hot path in
//! [`crate::merkle::verify`].

use crate::error::{Error, ErrorCode};
use crate::merkle::rfc6962::TreeHash;
use crate::merkle::tree::{largest_pow2_below, merkle_tree_hash};
use crate::wire::dec_u64;
use alloc::vec::Vec;

/// A node coordinate in the tree (level 0 = leaves). The injected-reader addressing seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeId {
    /// The level above the leaves (0 = a leaf).
    pub level: u8,
    /// The index within that level.
    #[serde(with = "dec_u64")]
    pub index: u64,
}

/// A source of perfect-subtree hashes, injected so proof construction never embeds storage (arch §6.3). A
/// storage-backed log implements this; the slice-based constructors below are the in-memory degenerate case.
pub trait MerkleReader {
    /// Read the hashes for the given node coordinates, in order.
    ///
    /// # Errors
    /// Returns an error if any node is unavailable.
    fn read_nodes(&self, ids: &[NodeId]) -> Result<Vec<TreeHash>, Error>;
}

/// An RFC 9162 inclusion proof: the audit path proving a leaf at `leaf_index` is in the tree of `tree_size`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    /// The 0-based index of the leaf.
    #[serde(with = "dec_u64")]
    pub leaf_index: u64,
    /// The size of the tree the proof is against.
    #[serde(with = "dec_u64")]
    pub tree_size: u64,
    /// The audit path (sibling subtree hashes), leaf-to-root order per RFC 9162.
    pub path: Vec<TreeHash>,
}

/// An RFC 9162 consistency proof between a tree of `first` leaves and one of `second` leaves.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProof {
    /// The size of the older tree.
    #[serde(with = "dec_u64")]
    pub first: u64,
    /// The size of the newer tree.
    #[serde(with = "dec_u64")]
    pub second: u64,
    /// The consistency path (RFC 9162 §2.1.4.1 order).
    pub path: Vec<TreeHash>,
}

/// `MTH(leaves[lo..hi])`, fail-closed on a bad range.
fn subtree_root(leaves: &[TreeHash], lo: u64, hi: u64) -> Result<TreeHash, Error> {
    let lo = usize::try_from(lo).map_err(|_| Error::internal("merkle.proof.lo"))?;
    let hi = usize::try_from(hi).map_err(|_| Error::internal("merkle.proof.hi"))?;
    let slice = leaves
        .get(lo..hi)
        .ok_or(Error::Inclusion(ErrorCode::MerkleIndexOutOfRange))?;
    Ok(merkle_tree_hash(slice))
}

/// True iff `n` is a power of two (`n >= 1`).
fn is_power_of_two(n: u64) -> bool {
    n != 0 && (n & n.wrapping_sub(1)) == 0
}

/// Build an inclusion proof for `leaf_index` over a full leaf-hash slice (RFC 6962 audit path).
///
/// # Errors
/// `MerkleIndexOutOfRange` if `leaf_index` is not within the slice.
pub fn inclusion_proof(leaves: &[TreeHash], leaf_index: u64) -> Result<InclusionProof, Error> {
    let n = u64::try_from(leaves.len()).map_err(|_| Error::internal("merkle.proof.len"))?;
    if leaf_index >= n {
        return Err(Error::Inclusion(ErrorCode::MerkleIndexOutOfRange));
    }
    // Build top-down (root split first); RFC 9162 verification walks leaf-to-root, so reverse before returning.
    // `m` stays the absolute leaf index; the [lo, hi) window narrows around it.
    let mut path = Vec::new();
    let m = leaf_index;
    let mut lo: u64 = 0;
    let mut hi: u64 = n;
    while hi.wrapping_sub(lo) > 1 {
        let k = largest_pow2_below(hi.wrapping_sub(lo));
        let mid = lo.wrapping_add(k);
        if m.wrapping_sub(lo) < k {
            path.push(subtree_root(leaves, mid, hi)?);
            hi = mid;
        } else {
            path.push(subtree_root(leaves, lo, mid)?);
            lo = mid;
        }
    }
    path.reverse();
    Ok(InclusionProof {
        leaf_index,
        tree_size: n,
        path,
    })
}

/// Build a consistency proof between the prefix of size `first` and the full slice (size `second`), per the
/// RFC 6962 SUBPROOF algorithm (iterative). The returned `path` excludes the implied `first_hash` when `first`
/// is a power of two (the verifier re-derives it).
///
/// # Errors
/// `ConsistencyProofInvalid` if `first` is 0 or greater than the slice length.
pub fn consistency_proof(leaves: &[TreeHash], first: u64) -> Result<ConsistencyProof, Error> {
    let n = u64::try_from(leaves.len()).map_err(|_| Error::internal("merkle.proof.len"))?;
    if first == 0 || first > n {
        return Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid));
    }
    if first == n {
        return Ok(ConsistencyProof {
            first,
            second: n,
            path: Vec::new(),
        });
    }
    // SUBPROOF(first, leaves[lo..hi], b) — collect siblings in iteration order, then assemble RFC order.
    let mut sibs: Vec<TreeHash> = Vec::new();
    let mut m = first;
    let mut lo: u64 = 0;
    let mut hi: u64 = n;
    let mut on_left_edge = true;
    while m < hi.wrapping_sub(lo) {
        let k = largest_pow2_below(hi.wrapping_sub(lo));
        let mid = lo.wrapping_add(k);
        if m <= k {
            sibs.push(subtree_root(leaves, mid, hi)?);
            hi = mid;
        } else {
            sibs.push(subtree_root(leaves, lo, mid)?);
            m = m.wrapping_sub(k);
            lo = mid;
            on_left_edge = false;
        }
    }
    // Terminal: when the remaining subtree is NOT on the original left edge, its root is part of the proof.
    let mut path: Vec<TreeHash> = Vec::new();
    if !on_left_edge {
        path.push(subtree_root(leaves, lo, hi)?);
    }
    // RFC order = [terminal] ++ reverse(siblings).
    sibs.reverse();
    path.extend(sibs);
    Ok(ConsistencyProof {
        first,
        second: n,
        path,
    })
}

/// Whether `first` being a power of two means the verifier should prepend `first_hash` to the path (exposed so the
/// verifier and tests share the one rule).
#[must_use]
pub(crate) fn consistency_prepends_first_hash(first: u64) -> bool {
    is_power_of_two(first)
}
