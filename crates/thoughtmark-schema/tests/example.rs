// SPDX-License-Identifier: Apache-2.0
//! Worked-example tests (arch §5.11): the typed wire structs round-trip byte-identically to the frozen
//! `spec/vectors/` fixtures, and the derivations match the blessed corpus output. Integration tests opt out of the
//! no-panic wall (a panic IS the failure signal here) via the file-level allow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use thoughtmark_core::{canon, canonicalize};
use thoughtmark_schema::{
    CanonVersion, ContentDigest, HashAlg, RunManifest, SchemaVersion, Statement, Trail, Turn,
    manifest_id, trail_root, turn_id,
};

// The fixtures (and their blessed expected outputs) are the single source of truth — included from the corpus so
// the typed structs and the cross-language vectors can never drift.
const TURN0_JSON: &str = include_str!("../../../spec/vectors/turn/0001/input.json");
const TURN0_ID: &str = include_str!("../../../spec/vectors/turn/0001/turn_id.hex");
const TURN1_JSON: &str = include_str!("../../../spec/vectors/turn/0002/input.json");
const TURN1_ID: &str = include_str!("../../../spec/vectors/turn/0002/turn_id.hex");
const MANIFEST_JSON: &str = include_str!("../../../spec/vectors/manifest/0001/input.json");
const MANIFEST_ID: &str = include_str!("../../../spec/vectors/manifest/0001/manifest_id.hex");
const TRAIL_JSON: &str = include_str!("../../../spec/vectors/trail/0001/input.json");
const TRAIL_ROOT: &[u8] = include_bytes!("../../../spec/vectors/trail/0001/trail_root.json");
const STATEMENT_JSON: &str = include_str!("../../../spec/vectors/statement/0001/input.json");
const STATEMENT_CANON: &[u8] = include_bytes!("../../../spec/vectors/statement/0001/expected.bin");

/// A typed struct deserialized from `raw` must canonicalize to the SAME bytes as the raw fixture text — the
/// proof that the Rust wire form round-trips byte-identically (no added/dropped fields, no reshaped values).
fn assert_round_trips<T: serde::Serialize + serde::de::DeserializeOwned>(raw: &str) -> T {
    let value: T = serde_json::from_str(raw).unwrap();
    let from_struct = canonicalize(&value).unwrap();
    let from_raw = canon::canonicalize_str(raw).unwrap();
    assert_eq!(
        from_struct, from_raw,
        "typed struct did not round-trip byte-identically"
    );
    value
}

#[test]
fn turn0_round_trips_and_turn_id_matches_blessed() {
    let turn: Turn = assert_round_trips(TURN0_JSON);
    assert_eq!(turn_id(&turn).unwrap().0.to_hex(), TURN0_ID.trim());
}

#[test]
fn turn1_round_trips_and_turn_id_matches_blessed() {
    let turn: Turn = assert_round_trips(TURN1_JSON);
    assert_eq!(turn_id(&turn).unwrap().0.to_hex(), TURN1_ID.trim());
}

#[test]
fn manifest_round_trips_and_id_matches_blessed() {
    let rm: RunManifest = assert_round_trips(MANIFEST_JSON);
    assert_eq!(manifest_id(&rm).unwrap().to_hex(), MANIFEST_ID.trim());
}

#[test]
fn trail_root_matches_blessed_dual_digest() {
    let trail: Trail = assert_round_trips(TRAIL_JSON);
    let map = trail_root(&trail).unwrap();
    // The schema's BTreeMap-typed derivation must canonicalize to the same bytes the `trail_root` op blessed.
    assert_eq!(canonicalize(&map).unwrap(), TRAIL_ROOT);
}

#[test]
fn statement_round_trips_to_blessed_canon() {
    let stmt: Statement = serde_json::from_str(STATEMENT_JSON).unwrap();
    assert_eq!(canonicalize(&stmt).unwrap(), STATEMENT_CANON);
}

#[test]
fn content_digest_hashed_structurally_omits_salt() {
    // I5: a salted commitment carries NO salt on-ledger — the type has no `salt_hex` field at all.
    // (`serde_json::to_value` is the inspection path; `to_string` is a banned non-canonical serializer.)
    let body = ContentDigest::Hashed {
        alg: HashAlg::Blake3,
        digest_hex: "00".repeat(32),
    };
    let value = serde_json::to_value(&body).unwrap();
    let obj = value.as_object().unwrap();
    assert!(
        !obj.keys().any(|k| k.contains("salt")),
        "on-ledger content digest must never carry a salt: {value}"
    );
    assert_eq!(obj.get("kind").and_then(|k| k.as_str()), Some("hashed"));
}

#[test]
fn schema_version_serializes_as_object_not_array() {
    assert_eq!(
        serde_json::to_value(SchemaVersion::V1).unwrap(),
        serde_json::json!({ "major": 1, "minor": 0, "patch": 0 }),
    );
}

#[test]
fn canon_version_fails_closed_on_unknown() {
    assert!(serde_json::from_str::<CanonVersion>("\"tm-jcs-1\"").is_ok());
    assert!(serde_json::from_str::<CanonVersion>("\"tm-jcs-2\"").is_err());
    assert!(serde_json::from_str::<CanonVersion>("\"\"").is_err());
}

#[test]
fn deny_unknown_fields_rejects_extra_keys() {
    // An unexpected top-level field on a Turn fails closed (deny_unknown_fields).
    let mut value: serde_json::Value = serde_json::from_str(TURN0_JSON).unwrap();
    value.as_object_mut().unwrap().insert(
        "salt_hex".into(),
        serde_json::Value::String("deadbeef".into()),
    );
    assert!(serde_json::from_value::<Turn>(value).is_err());
}
