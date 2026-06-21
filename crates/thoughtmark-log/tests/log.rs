// SPDX-License-Identifier: Apache-2.0
//! `InMemoryStorage` invariants: its root equals the batch `merkle_tree_hash`; every appended leaf's inclusion
//! proof verifies against the storage root; every prefix's consistency proof reconciles; and the gap-free
//! sequencer accepts a current view and rejects a stale one. Integration tests opt out of the no-panic wall.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use proptest::prelude::*;
use thoughtmark_core::merkle::{hash_leaf, merkle_tree_hash, verify_consistency, verify_inclusion};
use thoughtmark_log::sequencer::next_index;
use thoughtmark_log::{InMemoryStorage, LogStorage};

#[test]
fn sequencer_is_gap_free() {
    assert_eq!(next_index(5, 5), Ok(5));
    // A stale writer (observed 5, log is at 6) is rejected — no gap or duplicate can commit.
    assert!(next_index(5, 6).is_err());
    assert!(next_index(6, 5).is_err());
}

proptest! {
    /// The storage root equals the batch Merkle tree hash, and append returns gap-free indices.
    #[test]
    fn root_matches_batch_and_indices_are_gap_free(records in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 0..40)) {
        let mut log = InMemoryStorage::new();
        for (i, r) in records.iter().enumerate() {
            let idx = log.append(r).unwrap();
            prop_assert_eq!(idx, i as u64);
        }
        let leaves: Vec<_> = records.iter().map(|r| hash_leaf(r)).collect();
        prop_assert_eq!(log.root(), merkle_tree_hash(&leaves));
        prop_assert_eq!(log.tree_size(), records.len() as u64);
    }

    /// Every appended leaf has an inclusion proof that verifies against the storage root.
    #[test]
    fn every_leaf_inclusion_verifies(records in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 1..40)) {
        let mut log = InMemoryStorage::new();
        for r in &records {
            log.append(r).unwrap();
        }
        let root = log.root();
        for (i, r) in records.iter().enumerate() {
            let proof = log.inclusion_proof(i as u64).unwrap();
            prop_assert!(verify_inclusion(&proof, &hash_leaf(r), &root).is_ok());
        }
    }

    /// Every prefix's consistency proof reconciles the prefix root and the current root.
    #[test]
    fn every_prefix_consistency_verifies(records in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 2..40)) {
        let mut full = InMemoryStorage::new();
        for r in &records {
            full.append(r).unwrap();
        }
        let new_root = full.root();
        for first in 1..records.len() {
            let mut prefix = InMemoryStorage::new();
            for r in &records[..first] {
                prefix.append(r).unwrap();
            }
            let old_root = prefix.root();
            let proof = full.consistency_proof(first as u64).unwrap();
            prop_assert!(verify_consistency(&proof, &old_root, &new_root).is_ok(), "consistency {first}->{} failed", records.len());
        }
    }
}
