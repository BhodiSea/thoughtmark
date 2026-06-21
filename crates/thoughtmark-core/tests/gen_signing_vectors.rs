// SPDX-License-Identifier: Apache-2.0
//! Gated generator for the signing conformance fixtures (run with `THOUGHTMARK_EMIT_SIGNING=1`). Produces the
//! Ed25519 accept case, the `verify_strict` boundary rejects (the non-canonical-`S` malleability vector is THE
//! cofactor case `verify_strict` closes), the DSSE spec PAE example, a deterministic `sign_statement` envelope,
//! its `verify_envelope` round-trip, and a `did:key` decode. `tm bless` then computes the expected outputs.
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
use thoughtmark_core::sign::Signer as _;
use thoughtmark_core::{TmSigner, encode_did_key};

/// The Ed25519 group order ell, little-endian — non-canonical `S' = S + ell` is `>= ell`, which `verify_strict`
/// rejects (the malleability / non-canonical-scalar vector).
const ELL_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn write_text(root: &Path, dir: &str, name: &str, bytes: &[u8]) {
    let path = root.join(dir);
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join(name), bytes).unwrap();
}

fn write_json(root: &Path, dir: &str, name: &str, value: &serde_json::Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    write_text(root, dir, name, &bytes);
}

/// `S + ell` as 32 little-endian bytes (no final carry for a canonical `S < ell`).
fn add_ell(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let v = u16::from(s[i]) + u16::from(ELL_LE[i]) + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    out
}

#[test]
fn emit_signing_vectors() {
    if std::env::var("THOUGHTMARK_EMIT_SIGNING").is_err() {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");

    let seed = [7u8; 32];
    let probe = TmSigner::from_seed(seed, String::new());
    let vk = *probe.verifying_key();
    let did = encode_did_key(&vk);
    let signer = TmSigner::from_seed(seed, did.clone());
    let pubkey = vk.to_bytes();

    // ed25519/0001 — a valid signature over a fixed message → accept.
    let msg = b"thoughtmark-ed25519-conformance";
    let sig = signer.sign(msg).0;
    write_json(
        &root,
        "ed25519/0001",
        "input.json",
        &serde_json::json!({
            "pubkey_hex": hex(&pubkey),
            "msg_hex": hex(msg),
            "sig_hex": hex(&sig),
        }),
    );

    // negative/0011 — non-canonical S (S + ell): a malleable variant verify_strict MUST reject.
    let mut malleable = sig;
    malleable[32..64].copy_from_slice(&add_ell(&sig[32..64]));
    write_json(
        &root,
        "negative/0011",
        "input.json",
        &serde_json::json!({
            "pubkey_hex": hex(&pubkey),
            "msg_hex": hex(msg),
            "sig_hex": hex(&malleable),
        }),
    );

    // negative/0012 — a tampered signature → SIG_INVALID.
    let mut wrong = sig;
    wrong[0] ^= 0xff;
    write_json(
        &root,
        "negative/0012",
        "input.json",
        &serde_json::json!({
            "pubkey_hex": hex(&pubkey),
            "msg_hex": hex(msg),
            "sig_hex": hex(&wrong),
        }),
    );

    // negative/0013 — a too-short public key → SIG_MALFORMED_KEY.
    write_json(
        &root,
        "negative/0013",
        "input.json",
        &serde_json::json!({
            "pubkey_hex": hex(&pubkey[..30]),
            "msg_hex": hex(msg),
            "sig_hex": hex(&sig),
        }),
    );

    // dsse/0001 — the DSSE spec PAE example (payloadType len 29, body "hello world" len 11).
    write_json(
        &root,
        "dsse/0001",
        "input.json",
        &serde_json::json!({
            "payload_type": "http://example.com/HelloWorld",
            "body_b64": base64::engine::general_purpose::STANDARD.encode(b"hello world"),
        }),
    );

    // dsse/0002 — sign a small statement deterministically → canonical DSSE envelope.
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://thoughtmark.dev/Provenance/v1",
        "subject": [{ "name": "trail:demo@1", "digest": { "blake3": "00", "sha256": "11" } }],
        "predicate": { "hello": "world" }
    });
    write_json(
        &root,
        "dsse/0002",
        "input.json",
        &serde_json::json!({
            "seed_hex": hex(&seed),
            "keyid": did.clone(),
            "statement": statement.clone(),
        }),
    );

    // dsse/0003 — verify the envelope produced above against the signer's did:key.
    let payload = thoughtmark_core::canonicalize(&statement).unwrap();
    let envelope = signer.sign_payload(&payload);
    write_json(
        &root,
        "dsse/0003",
        "input.json",
        &serde_json::json!({
            "envelope": serde_json::to_value(&envelope).unwrap(),
            "keys": [did.clone()],
        }),
    );

    // did/0001 — decode the signer's did:key back to its public key.
    write_text(&root, "did/0001", "input.txt", did.as_bytes());
}
