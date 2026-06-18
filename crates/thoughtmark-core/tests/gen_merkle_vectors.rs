// SPDX-License-Identifier: Apache-2.0
//! Gated generator for the Merkle conformance fixtures. Run once with `THOUGHTMARK_EMIT_MERKLE=1` to (re)write the
//! `spec/vectors/{merkle,inclusion,consistency}/` input files from the validated core; `tm bless` then computes the
//! expected outputs (base64 roots / the `{"ok":true}` success envelope). A no-op without the env var, so it stays
//! inert in CI. Integration tests opt out of the no-panic wall and the disallowed-serializer ban (writing fixture
//! JSON is not the hashed path).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::disallowed_methods
)]

use base64::Engine as _;
use std::fs;
use std::path::Path;
use thoughtmark_core::merkle::{
    TreeHash, consistency_proof, empty_root, hash_leaf, inclusion_proof, merkle_tree_hash,
};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn write_input(root: &Path, dir: &str, name: &str, value: &serde_json::Value) {
    let path = root.join(dir);
    fs::create_dir_all(&path).unwrap();
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path.join(name), bytes).unwrap();
}

fn records(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| vec![i as u8]).collect()
}

fn leaf_hashes(recs: &[Vec<u8>]) -> Vec<TreeHash> {
    recs.iter().map(|r| hash_leaf(r)).collect()
}

fn mutate(h: &TreeHash) -> TreeHash {
    let mut bytes = *h.as_bytes();
    bytes[0] ^= 0xff;
    TreeHash::from_bytes(bytes)
}

#[test]
fn emit_merkle_vectors() {
    if std::env::var("THOUGHTMARK_EMIT_MERKLE").is_err() {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");

    // merkle_root: empty, single, power-of-two (4, 8), and non-power-of-two (5, 7 — the strict-split guard).
    for (id, n) in [(1usize, 0usize), (2, 1), (3, 4), (4, 5), (5, 7), (6, 8)] {
        let leaves: Vec<String> = records(n).iter().map(|r| b64(r)).collect();
        write_input(
            &root,
            &format!("merkle/{id:04}"),
            "leaves.json",
            &serde_json::json!({ "leaves": leaves }),
        );
    }

    // inclusion: a middle leaf of a non-pow2 tree, the first leaf of a pow2 tree, the last leaf of a non-pow2 tree.
    for (id, n, idx) in [(1usize, 7usize, 3u64), (2, 8, 0), (3, 5, 4)] {
        let recs = records(n);
        let lh = leaf_hashes(&recs);
        let proof = inclusion_proof(&lh, idx).unwrap();
        write_input(
            &root,
            &format!("inclusion/{id:04}"),
            "input.json",
            &serde_json::json!({
                "leaf": b64(&recs[idx as usize]),
                "proof": serde_json::to_value(&proof).unwrap(),
                "root": serde_json::to_value(merkle_tree_hash(&lh)).unwrap(),
            }),
        );
    }

    // consistency: prefix into a non-pow2 tree, pow2 prefix into a pow2 tree, single-leaf prefix.
    for (id, first, n) in [(1usize, 3u64, 7usize), (2, 4, 8), (3, 1, 5)] {
        let recs = records(n);
        let lh = leaf_hashes(&recs);
        let proof = consistency_proof(&lh, first).unwrap();
        write_input(
            &root,
            &format!("consistency/{id:04}"),
            "input.json",
            &serde_json::json!({
                "proof": serde_json::to_value(&proof).unwrap(),
                "old_root": serde_json::to_value(merkle_tree_hash(&lh[..first as usize])).unwrap(),
                "new_root": serde_json::to_value(merkle_tree_hash(&lh)).unwrap(),
            }),
        );
    }

    // negatives.
    let recs = records(7);
    let lh = leaf_hashes(&recs);
    let tree_root = merkle_tree_hash(&lh);

    // negative/0008: a mutated audit-path element → MERKLE_PROOF_INVALID.
    let mut mutated = inclusion_proof(&lh, 3).unwrap();
    mutated.path[0] = mutate(&mutated.path[0]);
    write_input(
        &root,
        "negative/0008",
        "input.json",
        &serde_json::json!({
            "leaf": b64(&recs[3]),
            "proof": serde_json::to_value(&mutated).unwrap(),
            "root": serde_json::to_value(tree_root).unwrap(),
        }),
    );

    // negative/0009: a too-long audit path (proof-padding forgery) → MERKLE_PROOF_INVALID.
    let mut padded = inclusion_proof(&lh, 3).unwrap();
    padded.path.push(empty_root());
    write_input(
        &root,
        "negative/0009",
        "input.json",
        &serde_json::json!({
            "leaf": b64(&recs[3]),
            "proof": serde_json::to_value(&padded).unwrap(),
            "root": serde_json::to_value(tree_root).unwrap(),
        }),
    );

    // negative/0010: a consistency proof against a tampered new_root → CONSISTENCY_PROOF_INVALID.
    let cproof = consistency_proof(&lh, 3).unwrap();
    write_input(
        &root,
        "negative/0010",
        "input.json",
        &serde_json::json!({
            "proof": serde_json::to_value(&cproof).unwrap(),
            "old_root": serde_json::to_value(merkle_tree_hash(&lh[..3])).unwrap(),
            "new_root": serde_json::to_value(mutate(&tree_root)).unwrap(),
        }),
    );
}
