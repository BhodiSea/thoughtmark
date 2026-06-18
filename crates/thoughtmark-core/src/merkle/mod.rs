// SPDX-License-Identifier: Apache-2.0
//! The RFC 6962 / RFC 9162 transparency-log Merkle math (arch §6, ADR-0005, ADR-0013).
//!
//! Reimplemented in-house (ADR-0005) so the WASM build is byte-identical by construction; external CT crates serve
//! only as differential oracles. The tree is pinned to SHA-256 with a distinct [`TreeHash`] newtype (ADR-0013), so
//! a transparency-tree hash can never be confused with a Tier-0 content [`crate::Digest`]. The leaf/node `0x00` /
//! `0x01` prefixes are the only domain separation in the tree (never the §4.5 ASCII scheme).

pub mod proof;
pub mod rfc6962;
pub mod tree;
pub mod verify;

pub use proof::{
    ConsistencyProof, InclusionProof, MerkleReader, NodeId, consistency_proof, inclusion_proof,
};
pub use rfc6962::{LEAF_PREFIX, NODE_PREFIX, TreeHash, empty_root, hash_children, hash_leaf};
pub use tree::{TreeState, largest_pow2_below, merkle_tree_hash};
pub use verify::{verify_consistency, verify_inclusion};
