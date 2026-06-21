// SPDX-License-Identifier: Apache-2.0
//! The audited Merkle proof verifiers (arch §6.2) — the byte-identity-critical, WASM-stack-critical hot path.
//!
//! Both verifiers are **iterative** (constant stack — recursion would blow the WASM stack on a large tree), use
//! constant-time hash equality ([`TreeHash::ct_eq`]), take `&TreeHash` so "forgot to leaf-hash" is a type error,
//! and reject a path of the wrong length in BOTH directions: a too-long path trips the `sn == 0` guard mid-walk,
//! a too-short one leaves `sn != 0` at the end (closing the proof-padding forgery vector). They follow RFC 9162
//! §2.1.3.2 (inclusion) and §2.1.4.2 (consistency, dual-recompute of both the old and the new root).

use crate::error::{Error, ErrorCode};
use crate::merkle::proof::{ConsistencyProof, InclusionProof, consistency_prepends_first_hash};
use crate::merkle::rfc6962::{TreeHash, hash_children};
use alloc::vec::Vec;

/// Verify an inclusion proof: that `leaf_hash` is the leaf at `proof.leaf_index` in the tree of `proof.tree_size`
/// whose root is `root` (RFC 9162 §2.1.3.2).
///
/// # Errors
/// `MerkleIndexOutOfRange` if the index is out of range; `MerkleProofInvalid` if the path is the wrong length or
/// does not reconstruct `root`.
pub fn verify_inclusion(
    proof: &InclusionProof,
    leaf_hash: &TreeHash,
    root: &TreeHash,
) -> Result<(), Error> {
    if proof.leaf_index >= proof.tree_size {
        return Err(Error::Inclusion(ErrorCode::MerkleIndexOutOfRange));
    }
    let mut fnode = proof.leaf_index;
    let mut snode = proof.tree_size.wrapping_sub(1); // tree_size >= 1 here
    let mut r = *leaf_hash;
    for p in &proof.path {
        if snode == 0 {
            return Err(Error::Inclusion(ErrorCode::MerkleProofInvalid)); // path too long
        }
        if (fnode & 1) == 1 || fnode == snode {
            r = hash_children(p, &r);
            while (fnode & 1) == 0 && fnode != 0 {
                fnode = fnode.wrapping_shr(1);
                snode = snode.wrapping_shr(1);
            }
        } else {
            r = hash_children(&r, p);
        }
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    if snode == 0 && r.ct_eq(root) {
        Ok(())
    } else {
        Err(Error::Inclusion(ErrorCode::MerkleProofInvalid))
    }
}

/// Verify a consistency proof: that the tree of `proof.first` leaves (root `old_root`) is a prefix of the tree of
/// `proof.second` leaves (root `new_root`) (RFC 9162 §2.1.4.2). Recomputes BOTH roots from the path and compares
/// each.
///
/// # Errors
/// `ConsistencyProofInvalid` if the sizes are inconsistent or the path fails to reconcile both roots.
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: &TreeHash,
    new_root: &TreeHash,
) -> Result<(), Error> {
    let (first, second) = (proof.first, proof.second);
    if first > second {
        return Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid));
    }
    if first == 0 {
        // The empty tree is a prefix of any tree; the path must be empty.
        return if proof.path.is_empty() {
            Ok(())
        } else {
            Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid))
        };
    }
    if first == second {
        return if proof.path.is_empty() && old_root.ct_eq(new_root) {
            Ok(())
        } else {
            Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid))
        };
    }

    // Assemble the working node list: prepend old_root when `first` is a power of two (the verifier re-derives the
    // first node the prover omitted).
    let mut nodes: Vec<TreeHash> = Vec::with_capacity(proof.path.len().saturating_add(1));
    if consistency_prepends_first_hash(first) {
        nodes.push(*old_root);
    }
    nodes.extend_from_slice(&proof.path);
    let Some(&first_node) = nodes.first() else {
        return Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid));
    };

    let mut fnode = first.wrapping_sub(1); // first >= 1
    let mut snode = second.wrapping_sub(1); // second >= 1
    while (fnode & 1) == 1 {
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    let mut fr = first_node;
    let mut sr = first_node;
    for c in nodes.iter().skip(1) {
        if snode == 0 {
            return Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid));
        }
        if (fnode & 1) == 1 || fnode == snode {
            fr = hash_children(c, &fr);
            sr = hash_children(c, &sr);
            while (fnode & 1) == 0 && fnode != 0 {
                fnode = fnode.wrapping_shr(1);
                snode = snode.wrapping_shr(1);
            }
        } else {
            sr = hash_children(&sr, c);
        }
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    if fnode == 0 && fr.ct_eq(old_root) && sr.ct_eq(new_root) {
        Ok(())
    } else {
        Err(Error::Consistency(ErrorCode::ConsistencyProofInvalid))
    }
}
