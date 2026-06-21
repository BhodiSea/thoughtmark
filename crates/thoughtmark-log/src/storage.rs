// SPDX-License-Identifier: Apache-2.0
//! The `LogStorage` trait (arch §6.5).
//!
//! The seam every backend implements. All hashing delegates to `thoughtmark_core::merkle`, so the roots and
//! proofs are byte-identical to the pure verifier's. Drivers: [`crate::InMemoryStorage`] (here, drives the corpus);
//! `PostgresStorage` (the single-institution sequencer) and `TileStorage` (the public-log export) ship later.

use thoughtmark_core::merkle::{ConsistencyProof, InclusionProof, TreeHash};

/// A storage-layer error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    /// A leaf index was out of range for the current tree size.
    #[error("leaf index {index} out of range (tree size {size})")]
    IndexOutOfRange {
        /// The requested index.
        index: u64,
        /// The current tree size.
        size: u64,
    },
    /// A sequencing conflict (a concurrent writer advanced the log).
    #[error(transparent)]
    Conflict(#[from] crate::sequencer::SequenceError),
    /// A backend-specific failure.
    #[error("storage backend: {0}")]
    Backend(String),
}

/// An append-only Merkle log.
pub trait LogStorage {
    /// Append a raw leaf record, returning its gap-free, monotonically increasing index.
    ///
    /// # Errors
    /// A [`StorageError`] on a sequencing or backend failure.
    fn append(&mut self, leaf: &[u8]) -> Result<u64, StorageError>;

    /// The current number of leaves.
    fn tree_size(&self) -> u64;

    /// The current Merkle root.
    fn root(&self) -> TreeHash;

    /// An RFC 9162 inclusion proof for the leaf at `index` against the current tree.
    ///
    /// # Errors
    /// [`StorageError::IndexOutOfRange`] if `index >= tree_size`.
    fn inclusion_proof(&self, index: u64) -> Result<InclusionProof, StorageError>;

    /// An RFC 9162 consistency proof from a prefix of size `first` to the current tree.
    ///
    /// # Errors
    /// [`StorageError::IndexOutOfRange`] if `first` is 0 or greater than the current size.
    fn consistency_proof(&self, first: u64) -> Result<ConsistencyProof, StorageError>;
}
