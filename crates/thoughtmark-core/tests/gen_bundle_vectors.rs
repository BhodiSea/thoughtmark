// SPDX-License-Identifier: Apache-2.0
//! Gated generator for the bundle conformance fixtures (run with `THOUGHTMARK_EMIT_BUNDLE=1`). Assembles a
//! COMPLETE `ThoughtmarkBundle` — a DSSE-signed Statement, its Merkle inclusion proof, and a signed checkpoint —
//! and a malformed-media-type negative.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use std::fs;
use std::path::Path;
use thoughtmark_core::bundle::{VerificationMaterial, VerificationMethod};
use thoughtmark_core::merkle::{hash_leaf, inclusion_proof, merkle_tree_hash};
use thoughtmark_core::{
    BUNDLE_MEDIA_TYPE, BUNDLE_VERSION, Checkpoint, ThoughtmarkBundle, TmSigner, canonicalize,
    checkpoint_body, encode_did_key, sign_checkpoint,
};

fn write_json(root: &Path, dir: &str, name: &str, value: &serde_json::Value) {
    let path = root.join(dir);
    fs::create_dir_all(&path).unwrap();
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path.join(name), bytes).unwrap();
}

#[test]
fn emit_bundle_vectors() {
    if std::env::var("THOUGHTMARK_EMIT_BUNDLE").is_err() {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");

    let seed = [21u8; 32];
    let probe = TmSigner::from_seed(seed, String::new());
    let vk = *probe.verifying_key();
    let did = encode_did_key(&vk);
    let signer = TmSigner::from_seed(seed, did.clone());

    // The signed Statement (the leaf the log commits to).
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://thoughtmark.dev/Provenance/v1",
        "subject": [{ "name": "trail:bundle-demo@1", "digest": { "blake3": "00", "sha256": "11" } }],
        "predicate": { "demo": true }
    });
    let payload = canonicalize(&statement).unwrap();
    let envelope = signer.sign_payload(&payload);

    // A single-leaf tree over the statement payload; the inclusion proof is trivial (empty path, size 1).
    let leaves = [hash_leaf(&payload)];
    let inclusion = inclusion_proof(&leaves, 0).unwrap();
    let root_hash = merkle_tree_hash(&leaves);

    // A signed checkpoint over that root.
    let origin = "thoughtmark.dev/log/bundle-demo";
    let checkpoint = Checkpoint {
        origin: origin.to_string(),
        size: 1,
        root: root_hash,
        extensions: Vec::new(),
    };
    let note = sign_checkpoint(&checkpoint_body(&checkpoint), origin, &vk, &signer);

    let multibase = did.strip_prefix("did:key:").unwrap().to_string();
    let bundle = ThoughtmarkBundle {
        media_type: BUNDLE_MEDIA_TYPE.to_string(),
        bundle_version: BUNDLE_VERSION,
        canon_version: "tm-jcs-1".to_string(),
        envelope,
        verification_material: VerificationMaterial {
            verification_methods: vec![VerificationMethod {
                id: did.clone(),
                public_key_multibase: multibase,
            }],
        },
        inclusion,
        checkpoint: note,
        consistency: None,
        anchors: Vec::new(),
    };

    let value = serde_json::to_value(&bundle).unwrap();
    write_json(&root, "bundle/0001", "bundle.json", &value);

    // negative/0016 — a wrong media type → BUNDLE_SCHEMA_INVALID.
    let mut bad = value;
    bad.as_object_mut().unwrap().insert(
        "media_type".into(),
        serde_json::Value::String("application/json".into()),
    );
    write_json(&root, "negative/0016", "input.json", &bad);
}
