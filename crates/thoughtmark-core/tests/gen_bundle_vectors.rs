// SPDX-License-Identifier: Apache-2.0
//! Gated generator for the bundle + verify conformance fixtures (run with `THOUGHTMARK_EMIT_BUNDLE=1`).
//!
//! Assembles a COMPLETE, signed two-turn `ThoughtmarkBundle` — an AI `create` turn (with a stapled run manifest)
//! and a human `approve` turn — wraps the `Trail` prefix in a DSSE-signed in-toto Statement, builds its Merkle
//! inclusion proof + a signed checkpoint, and staples the canonical turn/manifest bodies so `verify()` can replay
//! the full contribution-lineage DAG offline. It then emits the `verify/*` op inputs (an all-pass case, a tampered
//! signature, an anchor-required failure, a policy-unsatisfied failure) plus the malformed-input negatives. The
//! expected outputs are produced by `tm bless`, never hand-written.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    clippy::too_many_lines
)]

use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use thoughtmark_core::bundle::{VerificationMaterial, VerificationMethod};
use thoughtmark_core::canon::domain::{MANIFEST, OBJECT, TURN};
use thoughtmark_core::merkle::{TreeHash, hash_leaf, inclusion_proof, merkle_tree_hash};
use thoughtmark_core::{
    BUNDLE_MEDIA_TYPE, BUNDLE_VERSION, Checkpoint, HashAlg, ThoughtmarkBundle, TmSigner,
    canonicalize, checkpoint_body, encode_did_key, hash_domain, sign_checkpoint,
};

fn write_json(root: &Path, dir: &str, name: &str, value: &Value) {
    let path = root.join(dir);
    fs::create_dir_all(&path).unwrap();
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path.join(name), bytes).unwrap();
}

/// The `TurnId` JSON for a canonical turn body: `hash_domain(BLAKE3, "thoughtmark.turn", body)` as a `Digest`.
fn turn_id(body: &[u8]) -> Value {
    serde_json::to_value(hash_domain(HashAlg::Blake3, TURN, body)).unwrap()
}

/// The dual `{blake3,sha256}` `trail_root` map over the canonical Trail bytes.
fn trail_root(trail_canon: &[u8]) -> Value {
    json!({
        "blake3": hash_domain(HashAlg::Blake3, OBJECT, trail_canon).to_hex(),
        "sha256": hash_domain(HashAlg::Sha256, OBJECT, trail_canon).to_hex(),
    })
}

#[test]
fn emit_bundle_vectors() {
    if std::env::var("THOUGHTMARK_EMIT_BUNDLE").is_err() {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");

    // One issuer key signs both the Statement and the checkpoint (keyname = origin).
    let seed = [21u8; 32];
    let probe = TmSigner::from_seed(seed, String::new());
    let vk = *probe.verifying_key();
    let issuer_did = encode_did_key(&vk);
    let signer = TmSigner::from_seed(seed, issuer_did.clone());
    let human_did = "did:web:example.org:alice";

    // A SECOND log key — a co-witness for the k-of-n checkpoint cases and an "untrusted/other" key for the
    // negative checkpoint cases. Never signs the base bundle.
    let seed2 = [22u8; 32];
    let probe2 = TmSigner::from_seed(seed2, String::new());
    let vk2 = *probe2.verifying_key();
    let key2_did = encode_did_key(&vk2);
    let signer2 = TmSigner::from_seed(seed2, key2_did.clone());

    // The AI run manifest (stapled; referenced by the create turn).
    let manifest = json!({
        "canon_version": "tm-jcs-1",
        "decoding": { "temperature_milli": 0, "top_p_milli": 1000 },
        "model_id": "demo-model",
        "provider": "demo-provider",
        "system_prompt_digest": { "alg": "blake3", "bytes_hex": "00".repeat(32) },
    });
    let manifest_body = canonicalize(&manifest).unwrap();
    let manifest_ref: Value =
        serde_json::to_value(hash_domain(HashAlg::Blake3, MANIFEST, &manifest_body)).unwrap();

    // Turn 1 — the AI `create`, referencing the manifest.
    let turn1 = json!({
        "canon_version": "tm-jcs-1",
        "ledger": { "entries": [
            { "action": "create", "attested_at": "1000", "attributed_to": { "id": issuer_did } }
        ]},
        "parents": [],
        "role": "ai",
        "run_manifest_ref": manifest_ref,
        "sequence": 0,
    });
    let turn1_body = canonicalize(&turn1).unwrap();
    let turn1_id = turn_id(&turn1_body);

    // Turn 2 — the human `approve`, parented on turn 1.
    let turn2 = json!({
        "canon_version": "tm-jcs-1",
        "ledger": { "entries": [
            { "action": "approve", "approval_scope": "reviewed", "attested_at": "2000",
              "attributed_to": { "id": human_did } }
        ]},
        "parents": [turn1_id],
        "role": "human",
        "sequence": 1,
    });
    let turn2_body = canonicalize(&turn2).unwrap();
    let turn2_id = turn_id(&turn2_body);

    // The Trail prefix (the predicate).
    let trail = json!({
        "canon_version": "tm-jcs-1",
        "created_attested_at": "1000",
        "head": turn2_id,
        "schema_version": { "major": 1, "minor": 0, "patch": 0 },
        "trail_id": "demo",
        "turns": [turn1_id, turn2_id],
    });
    let trail_canon = canonicalize(&trail).unwrap();

    // The signed in-toto Statement (the leaf the log commits to). tree_size = 1 (a single statement leaf).
    let statement = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": trail,
        "predicateType": "https://thoughtmark.dev/Provenance/v1",
        "subject": [{ "digest": trail_root(&trail_canon), "name": "trail:demo@1" }],
    });
    let payload = canonicalize(&statement).unwrap();
    let envelope = signer.sign_payload(&payload);

    // A single-leaf tree over the statement payload; trivial inclusion proof.
    let leaves = [hash_leaf(&payload)];
    let inclusion = inclusion_proof(&leaves, 0).unwrap();
    let root_hash = merkle_tree_hash(&leaves);

    // A signed checkpoint over that root (keyname = origin).
    let origin = "thoughtmark.dev/log/bundle-demo";
    let checkpoint = Checkpoint {
        origin: origin.to_string(),
        size: 1,
        root: root_hash,
        extensions: Vec::new(),
    };
    let note = sign_checkpoint(&checkpoint_body(&checkpoint), origin, &vk, &signer);

    let multibase = issuer_did.strip_prefix("did:key:").unwrap().to_string();
    let bundle = ThoughtmarkBundle {
        media_type: BUNDLE_MEDIA_TYPE.to_string(),
        bundle_version: BUNDLE_VERSION,
        canon_version: "tm-jcs-1".to_string(),
        envelope,
        verification_material: VerificationMaterial {
            verification_methods: vec![VerificationMethod {
                id: issuer_did.clone(),
                public_key_multibase: multibase.clone(),
            }],
        },
        inclusion,
        checkpoint: note,
        consistency: None,
        anchors: Vec::new(),
        turn_bodies: vec![turn1_body.clone(), turn2_body.clone()],
        run_manifests: vec![manifest_body.clone()],
    };
    let bundle_value = serde_json::to_value(&bundle).unwrap();

    // bundle/0001 — the structural `bundle_check` fixture.
    write_json(&root, "bundle/0001", "bundle.json", &bundle_value);

    // The base policy: trust the issuer for the envelope and the log; require both lifecycle actions.
    let policy = json!({
        "accepted_canon_versions": ["tm-jcs-1"],
        "max_clock_skew_ms": 0,
        "require_anchor": false,
        "required_actions": ["create", "approve"],
        "required_witnesses": 0,
        "trusted_keys": [issuer_did],
        "trusted_log_keys": [issuer_did],
    });
    let env = json!({ "now_unix_ms": "1750000000000" });

    // verify/0001 — the all-pass case.
    write_json(
        &root,
        "verify/0001",
        "input.json",
        &json!({ "bundle": bundle_value, "policy": policy, "env": env }),
    );

    // verify/0002 — a tampered signature: DsseSignature fails, the rest of the honesty report survives.
    let mut tampered = bundle_value.clone();
    let sig = tampered["envelope"]["signatures"][0]["sig"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = flip_first_b64_char(&sig);
    tampered["envelope"]["signatures"][0]["sig"] = json!(flipped);
    write_json(
        &root,
        "verify/0002",
        "input.json",
        &json!({ "bundle": tampered, "policy": policy, "env": env }),
    );

    // verify/0003 — require_anchor with no anchor present fails closed (anchoring is inert at 1.0).
    let mut anchor_policy = policy.clone();
    anchor_policy["require_anchor"] = json!(true);
    write_json(
        &root,
        "verify/0003",
        "input.json",
        &json!({ "bundle": bundle_value, "policy": anchor_policy, "env": env }),
    );

    // verify/0004 — a required action absent from the ledger → ContributionLineage POLICY_UNSATISFIED.
    let mut unmet_policy = policy.clone();
    unmet_policy["required_actions"] = json!(["reject"]);
    write_json(
        &root,
        "verify/0004",
        "input.json",
        &json!({ "bundle": bundle_value, "policy": unmet_policy, "env": env }),
    );

    // ── Red-team gate net: a vector that makes EACH of the otherwise-untested checks fail, each isolating ONE check
    // (a tamper is `total:false`, not an op error). A re-signing assembler builds a COMPLETE bundle around a
    // (possibly mutated) statement; honest inputs reproduce the base bundle byte-for-byte (signing is deterministic)
    // so only the mutation flips a check. Expected `result.json` is blessed by `tm bless`, never hand-written.
    let make_bundle = |statement: &Value,
                       root_override: Option<TreeHash>,
                       size_override: Option<u64>,
                       second_log: Option<&TmSigner>,
                       turn_bodies: Vec<Vec<u8>>,
                       run_manifests: Vec<Vec<u8>>|
     -> Value {
        let payload = canonicalize(statement).unwrap();
        let envelope = signer.sign_payload(&payload);
        let leaves = [hash_leaf(&payload)];
        let inclusion = inclusion_proof(&leaves, 0).unwrap();
        let root = root_override.unwrap_or_else(|| merkle_tree_hash(&leaves));
        let size = size_override.unwrap_or(1);
        let cp = Checkpoint {
            origin: origin.to_string(),
            size,
            root,
            extensions: Vec::new(),
        };
        let body = checkpoint_body(&cp);
        let mut note = sign_checkpoint(&body, origin, &vk, &signer);
        if let Some(s2) = second_log {
            // Append a second cosignature line: everything in s2's note after the blank-line separator (body+`\n`).
            let note2 = sign_checkpoint(&body, origin, s2.verifying_key(), s2);
            note.extend_from_slice(&note2[body.len() + 1..]);
        }
        let bundle = ThoughtmarkBundle {
            media_type: BUNDLE_MEDIA_TYPE.to_string(),
            bundle_version: BUNDLE_VERSION,
            canon_version: "tm-jcs-1".to_string(),
            envelope,
            verification_material: VerificationMaterial {
                verification_methods: vec![VerificationMethod {
                    id: issuer_did.clone(),
                    public_key_multibase: multibase.clone(),
                }],
            },
            inclusion,
            checkpoint: note,
            consistency: None,
            anchors: Vec::new(),
            turn_bodies,
            run_manifests,
        };
        serde_json::to_value(&bundle).unwrap()
    };
    let write_verify = |name: &str, bundle: &Value, pol: &Value| {
        write_json(
            &root,
            &format!("verify/{name}"),
            "input.json",
            &json!({ "bundle": bundle, "policy": pol, "env": env }),
        );
    };
    let honest_turns = || vec![turn1_body.clone(), turn2_body.clone()];
    let honest_manifests = || vec![manifest_body.clone()];

    // verify/0005 — k-of-n 2-of-2 PASS: two DISTINCT trusted log keys cosign; required_witnesses=2 (count==floor).
    let kofn = make_bundle(
        &statement,
        None,
        None,
        Some(&signer2),
        honest_turns(),
        honest_manifests(),
    );
    let mut kofn_policy = policy.clone();
    kofn_policy["required_witnesses"] = json!(2);
    kofn_policy["trusted_log_keys"] = json!([issuer_did.clone(), key2_did.clone()]);
    write_verify("0005", &kofn, &kofn_policy);

    // verify/0006 — BundleSchema: an unsupported bundle_version (canon stays valid → only this check fails).
    let mut bad_version = bundle_value.clone();
    bad_version["bundle_version"] = json!(2);
    write_verify("0006", &bad_version, &policy);

    // verify/0007 — CanonVersion: the bundle's canon version is not policy-accepted (shape still valid).
    let mut no_canon = policy.clone();
    no_canon["accepted_canon_versions"] = json!([]);
    write_verify("0007", &bundle_value, &no_canon);

    // verify/0008 — StatementBinding: a corrupted subject digest (re-signed) ≠ the recomputed trail_root.
    let mut stmt_digest = statement.clone();
    let good_b3 = stmt_digest["subject"][0]["digest"]["blake3"]
        .as_str()
        .unwrap()
        .to_string();
    stmt_digest["subject"][0]["digest"]["blake3"] = json!(flip_first_hex_char(&good_b3));
    let b = make_bundle(
        &stmt_digest,
        None,
        None,
        None,
        honest_turns(),
        honest_manifests(),
    );
    write_verify("0008", &b, &policy);

    // verify/0009 — StatementBinding: the bound tree_size ("@2") ≠ the inclusion proof's (1). Kills checks.rs:255.
    let mut stmt_size = statement.clone();
    stmt_size["subject"][0]["name"] = json!("trail:demo@2");
    let b = make_bundle(
        &stmt_size,
        None,
        None,
        None,
        honest_turns(),
        honest_manifests(),
    );
    write_verify("0009", &b, &policy);

    // verify/0010 — StatementBinding: a policy expected_subject_digest that does not match the bound digest.
    let mut exp_policy = policy.clone();
    exp_policy["expected_subject_digest"] =
        json!({ "alg": "blake3", "bytes_hex": "11".repeat(32) });
    write_verify("0010", &bundle_value, &exp_policy);

    // verify/0011 — StatementBinding: a non-singleton subject set (re-signed). Exercises the len!=1 reject.
    let mut stmt_multi = statement.clone();
    let dup_subject = stmt_multi["subject"][0].clone();
    stmt_multi["subject"] = json!([dup_subject.clone(), dup_subject]);
    let b = make_bundle(
        &stmt_multi,
        None,
        None,
        None,
        honest_turns(),
        honest_manifests(),
    );
    write_verify("0011", &b, &policy);

    // verify/0012 — MerkleInclusion: the leaf is not under the (re-signed) bogus checkpoint root.
    let bogus_root = merkle_tree_hash(&[hash_leaf(b"not the statement leaf")]);
    let b = make_bundle(
        &statement,
        Some(bogus_root),
        None,
        None,
        honest_turns(),
        honest_manifests(),
    );
    write_verify("0012", &b, &policy);

    // verify/0013 — Checkpoint: the sole cosignature is from an untrusted log key (count 0 < floor 1).
    let mut other_log = policy.clone();
    other_log["trusted_log_keys"] = json!([key2_did.clone()]);
    write_verify("0013", &bundle_value, &other_log);

    // verify/0014 — Checkpoint: a k-of-n shortfall (required_witnesses=2 but only one key cosigned).
    let mut shortfall = policy.clone();
    shortfall["required_witnesses"] = json!(2);
    shortfall["trusted_log_keys"] = json!([issuer_did.clone(), key2_did.clone()]);
    write_verify("0014", &bundle_value, &shortfall);

    // verify/0015 — Checkpoint: the policy log_origin does not match the checkpoint origin.
    let mut wrong_origin = policy.clone();
    wrong_origin["log_origin"] = json!("thoughtmark.dev/log/not-this-one");
    write_verify("0015", &bundle_value, &wrong_origin);

    // verify/0016 — MerkleInclusion: the SIGNED checkpoint size (2) ≠ the inclusion proof's tree_size (1).
    let b = make_bundle(
        &statement,
        None,
        Some(2),
        None,
        honest_turns(),
        honest_manifests(),
    );
    write_verify("0016", &b, &policy);

    // verify/0017 — ContributionLineage: a declared turn with no stapled body (mandatory lineage; R4).
    let b = make_bundle(
        &statement,
        None,
        None,
        None,
        vec![turn1_body.clone()],
        honest_manifests(),
    );
    write_verify("0017", &b, &policy);

    // verify/0018 — ContributionLineage: a duplicate stapled turn body (the same turn id twice).
    let b = make_bundle(
        &statement,
        None,
        None,
        None,
        vec![turn1_body.clone(), turn1_body.clone()],
        honest_manifests(),
    );
    write_verify("0018", &b, &policy);

    // verify/0019 — ContributionLineage: a run_manifest_ref with no stapled manifest.
    let b = make_bundle(&statement, None, None, None, honest_turns(), Vec::new());
    write_verify("0019", &b, &policy);

    // negative/0016 — a wrong media type → BUNDLE_SCHEMA_INVALID (bundle_check, unchanged).
    let mut bad = bundle_value;
    bad.as_object_mut()
        .unwrap()
        .insert("media_type".into(), json!("application/json"));
    write_json(&root, "negative/0016", "input.json", &bad);

    // negative/0044 — a malformed verify input (bundle is not an object) → BUNDLE_SCHEMA_INVALID.
    write_json(
        &root,
        "negative/0044",
        "input.json",
        &json!({ "bundle": "not-an-object", "policy": policy, "env": env }),
    );
}

/// Flip the first base64 character of a signature so it decodes to different bytes (a clean tamper).
fn flip_first_b64_char(sig: &str) -> String {
    let mut chars: Vec<char> = sig.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = if *first == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

/// Flip the first hex character of a digest so it no longer matches the recomputed value (a clean tamper).
fn flip_first_hex_char(hex: &str) -> String {
    let mut chars: Vec<char> = hex.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = if *first == '0' { '1' } else { '0' };
    }
    chars.into_iter().collect()
}
