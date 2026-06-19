// SPDX-License-Identifier: Apache-2.0
//! `InMemoryStorage` — the `Vec`-backed driver that drives the conformance corpus (arch §6.5).
//!
//! All hashing delegates to `thoughtmark_core::merkle`: it holds the leaf hashes and an incremental
//! [`thoughtmark_core::merkle::TreeState`] so its root is, by construction, the same root the pure verifier
//! recomputes.

use crate::sequencer::next_index;
use crate::storage::{LogStorage, StorageError};
use thoughtmark_core::merkle::{
    ConsistencyProof, InclusionProof, TreeHash, TreeState, consistency_proof, hash_leaf,
    inclusion_proof,
};

/// A `Vec`-backed append-only Merkle log.
#[derive(Default)]
pub struct InMemoryStorage {
    leaf_hashes: Vec<TreeHash>,
    state: TreeState,
}

impl InMemoryStorage {
    /// A new empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl LogStorage for InMemoryStorage {
    fn append(&mut self, leaf: &[u8]) -> Result<u64, StorageError> {
        // The next index is the current size (single-writer); the sequencer guard makes the gap-free invariant
        // explicit and shared with the concurrent (Postgres) driver.
        let index = next_index(self.state.size(), self.state.size())?;
        let leaf_hash = hash_leaf(leaf);
        self.leaf_hashes.push(leaf_hash);
        self.state.append_leaf_hash(leaf_hash);
        Ok(index)
    }

    fn tree_size(&self) -> u64 {
        self.state.size()
    }

    fn root(&self) -> TreeHash {
        self.state.root()
    }

    fn inclusion_proof(&self, index: u64) -> Result<InclusionProof, StorageError> {
        inclusion_proof(&self.leaf_hashes, index).map_err(|_| StorageError::IndexOutOfRange {
            index,
            size: self.tree_size(),
        })
    }

    fn consistency_proof(&self, first: u64) -> Result<ConsistencyProof, StorageError> {
        consistency_proof(&self.leaf_hashes, first).map_err(|_| StorageError::IndexOutOfRange {
            index: first,
            size: self.tree_size(),
        })
    }
}
