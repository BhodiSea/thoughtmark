// SPDX-License-Identifier: Apache-2.0
//! RFC 6962 / RFC 9162 Merkle math: construction ↔ verification round-trips for every tree size and leaf index,
//! consistency between every prefix, incremental `TreeState` equals the batch root, and the forgery guards
//! (mutated / too-long / too-short proofs all fail). Known SHA-256 constants anchor the absolute byte values.
//! Integration tests opt out of the no-panic wall — a panic IS the failure signal.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use proptest::prelude::*;
use thoughtmark_core::merkle::{
    TreeHash, TreeState, consistency_proof, empty_root, hash_leaf, inclusion_proof,
    merkle_tree_hash, verify_consistency, verify_inclusion,
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `n` distinct leaf hashes (the record is the little-endian index, so all leaves differ).
fn leaves(n: usize) -> Vec<TreeHash> {
    (0..n).map(|i| hash_leaf(&i.to_le_bytes())).collect()
}

#[test]
fn empty_root_is_sha256_of_empty_string() {
    assert_eq!(
        hex(empty_root().as_bytes()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn single_empty_leaf_is_sha256_of_0x00() {
    // RFC 6962 hash_leaf("") = SHA-256(0x00). The canonical CT empty-leaf hash.
    assert_eq!(
        hex(hash_leaf(b"").as_bytes()),
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
}

#[test]
fn merkle_tree_hash_of_one_leaf_is_the_leaf() {
    let h = hash_leaf(b"x");
    assert_eq!(merkle_tree_hash(&[h]), h);
}

proptest! {
    /// Every leaf of every tree (sizes 1..=64) has an inclusion proof that verifies against the batch root.
    #[test]
    fn inclusion_round_trips(n in 1usize..=64, idx in 0usize..64) {
        prop_assume!(idx < n);
        let ls = leaves(n);
        let root = merkle_tree_hash(&ls);
        let proof = inclusion_proof(&ls, idx as u64).unwrap();
        prop_assert!(verify_inclusion(&proof, &ls[idx], &root).is_ok());
    }

    /// Every prefix size `first` of every tree size `second` has a consistency proof that reconciles both roots.
    #[test]
    fn consistency_round_trips(second in 1usize..=64, first in 1usize..=64) {
        prop_assume!(first <= second);
        let ls = leaves(second);
        let old_root = merkle_tree_hash(&ls[..first]);
        let new_root = merkle_tree_hash(&ls);
        let proof = consistency_proof(&ls, first as u64).unwrap();
        prop_assert!(
            verify_consistency(&proof, &old_root, &new_root).is_ok(),
            "consistency {first}->{second} failed"
        );
    }

    /// The incremental `TreeState` root equals the batch `merkle_tree_hash` at every size.
    #[test]
    fn treestate_matches_batch(n in 0usize..=64) {
        let records: Vec<Vec<u8>> = (0..n).map(|i| i.to_le_bytes().to_vec()).collect();
        let mut state = TreeState::empty();
        for r in &records {
            state.append_leaf(r);
        }
        let ls: Vec<TreeHash> = records.iter().map(|r| hash_leaf(r)).collect();
        prop_assert_eq!(state.root(), merkle_tree_hash(&ls));
        prop_assert_eq!(state.size(), n as u64);
    }

    /// A mutated audit-path element fails verification.
    #[test]
    fn mutated_inclusion_proof_fails(n in 2usize..=32, idx in 0usize..32) {
        prop_assume!(idx < n);
        let ls = leaves(n);
        let root = merkle_tree_hash(&ls);
        let mut proof = inclusion_proof(&ls, idx as u64).unwrap();
        prop_assume!(!proof.path.is_empty());
        let mut bytes = *proof.path[0].as_bytes();
        bytes[0] ^= 0xff;
        proof.path[0] = TreeHash::from_bytes(bytes);
        prop_assert!(verify_inclusion(&proof, &ls[idx], &root).is_err());
    }

    /// A too-long or too-short audit path fails (the proof-padding forgery guard, both directions).
    #[test]
    fn wrong_length_inclusion_proof_fails(n in 2usize..=32, idx in 0usize..32) {
        prop_assume!(idx < n);
        let ls = leaves(n);
        let root = merkle_tree_hash(&ls);
        let valid = inclusion_proof(&ls, idx as u64).unwrap();

        let mut too_long = valid.clone();
        too_long.path.push(empty_root());
        prop_assert!(verify_inclusion(&too_long, &ls[idx], &root).is_err(), "too-long path accepted");

        if !valid.path.is_empty() {
            let mut too_short = valid.clone();
            too_short.path.pop();
            prop_assert!(verify_inclusion(&too_short, &ls[idx], &root).is_err(), "too-short path accepted");
        }
    }
}
