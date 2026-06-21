// SPDX-License-Identifier: Apache-2.0
//! The Merkle Tree Hash and incremental tree state (arch §6.2, §6.3).
//!
//! RFC 6962 splits `D[n]` (n > 1) at the **largest power of two strictly less than n** — a naive `n/2` split is a
//! classic bug that passes only on powers of two ([`largest_pow2_below`] pins the right rule). [`merkle_tree_hash`]
//! computes the root iteratively via the equivalent streaming merge (merge equal-sized subtrees from the left),
//! so it is constant-stack — recursion would blow the WASM stack on a large tree. [`TreeState`] carries the
//! right-edge fringe (the streaming stack), which is exactly what an incremental [`TreeState::append_leaf`] needs
//! to recompute the new root from the prior state plus one leaf.

use crate::merkle::rfc6962::{TreeHash, empty_root, hash_children, hash_leaf};
use alloc::vec::Vec;

/// The largest power of two **strictly less than** `n` (defined for `n >= 2`). `k = 1 << (63 - (n-1).leading_zeros())`.
/// Returns `1` for `n < 2` (degenerate; callers never split a 0/1-leaf range).
#[must_use]
pub fn largest_pow2_below(n: u64) -> u64 {
    if n < 2 {
        return 1;
    }
    let shift = (u64::BITS - 1).saturating_sub(n.saturating_sub(1).leading_zeros());
    1u64.checked_shl(shift).unwrap_or(1)
}

/// Combine a streaming fringe (subtree roots, leftmost first) into a single root, folding right-to-left so each
/// earlier (larger, left) subtree becomes the left child of the running root.
fn combine_fringe(fringe: &[TreeHash]) -> TreeHash {
    let mut iter = fringe.iter().rev();
    match iter.next() {
        None => empty_root(),
        Some(&last) => {
            let mut root = last;
            for left in iter {
                root = hash_children(left, &root);
            }
            root
        }
    }
}

/// `MTH(leaves)` over already-leaf-hashed inputs (RFC 6962 §2.1), computed iteratively. `leaves` are the outputs
/// of [`hash_leaf`]; an empty slice hashes to [`empty_root`].
#[must_use]
pub fn merkle_tree_hash(leaves: &[TreeHash]) -> TreeHash {
    // (subtree root, leaf count) stack; merge whenever the top subtree has the same size as the incoming one.
    let mut stack: Vec<(TreeHash, u64)> = Vec::new();
    for leaf in leaves {
        let mut node = *leaf;
        let mut size: u64 = 1;
        while let Some(&(top, top_size)) = stack.last() {
            if top_size != size {
                break;
            }
            stack.pop();
            node = hash_children(&top, &node);
            size = size.saturating_mul(2);
        }
        stack.push((node, size));
    }
    let roots: Vec<TreeHash> = stack.into_iter().map(|(h, _)| h).collect();
    combine_fringe(&roots)
}

/// The state of a transparency tree: its size, current root, and the right-edge fringe needed to append.
#[derive(Clone)]
pub struct TreeState {
    size: u64,
    root: TreeHash,
    /// The streaming stack: perfect-subtree roots with their (power-of-two) leaf counts, leftmost first.
    fringe: Vec<(TreeHash, u64)>,
}

impl TreeState {
    /// The empty tree (`size = 0`, `root = SHA-256("")`).
    #[must_use]
    pub fn empty() -> Self {
        TreeState {
            size: 0,
            root: empty_root(),
            fringe: Vec::new(),
        }
    }

    /// The number of leaves appended so far.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The current Merkle root.
    #[must_use]
    pub const fn root(&self) -> TreeHash {
        self.root
    }

    /// Append a raw leaf record (applies [`hash_leaf`]).
    pub fn append_leaf(&mut self, record: &[u8]) {
        self.append_leaf_hash(hash_leaf(record));
    }

    /// Append an already-leaf-hashed value, recomputing the root from the prior fringe (constant work per append
    /// amortized; the fringe is `O(log n)`).
    pub fn append_leaf_hash(&mut self, leaf: TreeHash) {
        let mut node = leaf;
        let mut size: u64 = 1;
        while let Some(&(top, top_size)) = self.fringe.last() {
            if top_size != size {
                break;
            }
            self.fringe.pop();
            node = hash_children(&top, &node);
            size = size.saturating_mul(2);
        }
        self.fringe.push((node, size));
        self.size = self.size.saturating_add(1);
        let roots: Vec<TreeHash> = self.fringe.iter().map(|(h, _)| *h).collect();
        self.root = combine_fringe(&roots);
    }
}

impl Default for TreeState {
    fn default() -> Self {
        TreeState::empty()
    }
}
