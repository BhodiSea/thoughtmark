// SPDX-License-Identifier: Apache-2.0
//! Gated generator for the checkpoint conformance fixtures (run with `THOUGHTMARK_EMIT_CHECKPOINT=1`). Emits a
//! `checkpoint_body` case, a `checkpoint_verify` accept case, and the two exactness-trap negatives: a hyphen in
//! place of the em-dash, and a signature for a different keyname (the ≥1-matched-signature requirement).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use base64::Engine as _;
use std::fs;
use std::path::Path;
use thoughtmark_core::{
    Checkpoint, TmSigner, TreeHash, checkpoint_body, encode_did_key, sign_checkpoint,
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn write_json(root: &Path, dir: &str, name: &str, value: &serde_json::Value) {
    let path = root.join(dir);
    fs::create_dir_all(&path).unwrap();
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path.join(name), bytes).unwrap();
}

#[test]
fn emit_checkpoint_vectors() {
    if std::env::var("THOUGHTMARK_EMIT_CHECKPOINT").is_err() {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");

    let seed = [13u8; 32];
    let probe = TmSigner::from_seed(seed, String::new());
    let vk = *probe.verifying_key();
    let did = encode_did_key(&vk);
    let signer = TmSigner::from_seed(seed, did);
    let keyname = "thoughtmark.dev/log/demo";

    let checkpoint = Checkpoint {
        origin: keyname.to_string(),
        size: 42,
        root: TreeHash::from_bytes([0xab; 32]),
        extensions: Vec::new(),
    };
    let body = checkpoint_body(&checkpoint);

    // checkpoint/0001 — the deterministic note body.
    write_json(
        &root,
        "checkpoint/0001",
        "input.json",
        &serde_json::to_value(&checkpoint).unwrap(),
    );

    // checkpoint/0002 — a valid signed note → verifies.
    let note = sign_checkpoint(&body, keyname, &vk, &signer);
    write_json(
        &root,
        "checkpoint/0002",
        "input.json",
        &serde_json::json!({
            "note_b64": b64(&note),
            "keyname": keyname,
            "pubkey_hex": hex(&vk.to_bytes()),
        }),
    );

    // negative/0014 — a hyphen in place of the em-dash: no signature line is recognized.
    let mut hyphenated = note.clone();
    if let Some(pos) = hyphenated.windows(3).position(|w| w == [0xe2, 0x80, 0x94]) {
        hyphenated.splice(pos..pos + 3, [b'-']);
    }
    write_json(
        &root,
        "negative/0014",
        "input.json",
        &serde_json::json!({
            "note_b64": b64(&hyphenated),
            "keyname": keyname,
            "pubkey_hex": hex(&vk.to_bytes()),
        }),
    );

    // negative/0015 — the signature is for a different keyname: zero lines match (the ≥1-matched-sig trap).
    write_json(
        &root,
        "negative/0015",
        "input.json",
        &serde_json::json!({
            "note_b64": b64(&note),
            "keyname": "some.other.log",
            "pubkey_hex": hex(&vk.to_bytes()),
        }),
    );
}
