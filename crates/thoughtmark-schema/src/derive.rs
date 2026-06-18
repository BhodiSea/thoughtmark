// SPDX-License-Identifier: Apache-2.0
//! Pure derivations over the wire types (arch §5.8, §5.10).
//!
//! These route through the single `thoughtmark_core::canon` choke point (I2: JCS-before-hash) and the
//! domain-separated content hash (arch §4.5). [`turn_id`]/[`manifest_id`]/[`trail_root`] are byte-identity-critical
//! and are pinned by the cross-language corpus (the conformance ops `hash_domain_turn`/`hash_domain_manifest`/
//! `trail_root` compute the same bytes from raw JSON). [`export_prov`] is **lossy, one-way, and NEVER hashed**
//! (P6) — RDF-dataset canonicalization is off the trusted path.

use crate::manifest::RunManifest;
use crate::turn::{Trail, Turn, TurnId};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use thoughtmark_core::canon::domain::{MANIFEST, OBJECT, TURN};
use thoughtmark_core::{Digest, Error, HashAlg, canonicalize, hash_domain};

/// `turn_id = hash_domain(BLAKE3, "thoughtmark.turn", canonicalize(turn))` (arch §5.8, SCHEMA-2).
///
/// # Errors
/// Returns a canonicalization error if the turn carries a float or out-of-range integer on the hashed path.
pub fn turn_id(turn: &Turn) -> Result<TurnId, Error> {
    let canon = canonicalize(turn)?;
    Ok(TurnId(hash_domain(HashAlg::Blake3, TURN, &canon)))
}

/// `manifest_id = hash_domain(BLAKE3, "thoughtmark.manifest", canonicalize(rm))` (arch §5.7, SCHEMA-2).
///
/// # Errors
/// Returns a canonicalization error if the manifest carries a float or out-of-range integer.
pub fn manifest_id(rm: &RunManifest) -> Result<Digest, Error> {
    let canon = canonicalize(rm)?;
    Ok(hash_domain(HashAlg::Blake3, MANIFEST, &canon))
}

/// `trail_root` = the dual `{"blake3":hex,"sha256":hex}` map of `hash_domain(alg, "thoughtmark.object",
/// canonicalize(trail))` (arch §5.8, SCHEMA-3). Both digests are over the SAME canonical bytes.
///
/// # Errors
/// Returns a canonicalization error if the trail carries a float or out-of-range integer.
pub fn trail_root(trail: &Trail) -> Result<BTreeMap<String, String>, Error> {
    let canon = canonicalize(trail)?;
    let blake3 = hash_domain(HashAlg::Blake3, OBJECT, &canon);
    let sha256 = hash_domain(HashAlg::Sha256, OBJECT, &canon);
    let mut map = BTreeMap::new();
    map.insert("blake3".to_string(), blake3.to_hex());
    map.insert("sha256".to_string(), sha256.to_hex());
    Ok(map)
}

/// Export a PROV-O view of a trail (arch §5.10). **Lossy, one-way, and NEVER hashed** (P6): JSON-LD requires RDF
/// Dataset Canonicalization, a divergence-prone algorithm distinct from JCS — hashing this would forfeit
/// byte-identity. The native schema is the sole oracle; this is a derived consumer view only.
///
/// Mapping: a `Turn` → a `prov:Entity`; a `LedgerEntry` → a `prov:Activity` (typed by the verb); a credited DID →
/// a `prov:Agent` (subtyped `tm:AIAgent` when it acts on an AI/System/Tool turn); `parents` → `prov:wasDerivedFrom`;
/// `supersedes` → `tm:supersedes`; an AI turn's manifest → a `prov:Entity` the activity `prov:used`.
#[must_use]
pub fn export_prov(trail: &Trail, turns: &[Turn], manifests: &[RunManifest]) -> serde_json::Value {
    use serde_json::{Map, Value};

    let mut graph: Vec<Value> = Vec::new();
    graph.push(node_with_type(
        format!("tm:trail/{}", trail.trail_id),
        type_single("prov:Entity"),
    ));
    for (i, turn) in turns.iter().enumerate() {
        push_turn_nodes(&mut graph, &trail.trail_id, i, turn);
    }
    for (did, is_ai) in &collect_agent_is_ai(turns) {
        let ty = if *is_ai {
            type_pair("prov:Agent", "tm:AIAgent")
        } else {
            type_single("prov:Agent")
        };
        graph.push(node_with_type(did.clone(), ty));
    }
    for (i, _rm) in manifests.iter().enumerate() {
        graph.push(node_with_type(
            format!("tm:manifest/{i}"),
            type_pair("prov:Entity", "tm:RunManifest"),
        ));
    }

    let mut root = Map::new();
    root.insert(
        "@context".to_string(),
        Value::String("https://www.w3.org/ns/prov".to_string()),
    );
    root.insert("@graph".to_string(), Value::Array(graph));
    Value::Object(root)
}

/// Which DIDs act on AI/System/Tool turns → subtype them `tm:AIAgent`. Deterministic (`BTreeMap`).
fn collect_agent_is_ai(turns: &[Turn]) -> BTreeMap<String, bool> {
    use crate::turn::TurnRole;
    let mut agent_is_ai: BTreeMap<String, bool> = BTreeMap::new();
    for turn in turns {
        let acts_ai = !matches!(turn.role, TurnRole::Human);
        for entry in &turn.ledger.entries {
            let did = entry.attributed_to.id.clone();
            let prior = agent_is_ai.get(&did).copied().unwrap_or(false);
            agent_is_ai.insert(did, prior || acts_ai);
        }
    }
    agent_is_ai
}

/// Append a turn's `prov:Entity` and one `prov:Activity` per ledger entry.
fn push_turn_nodes(graph: &mut Vec<serde_json::Value>, trail_id: &str, i: usize, turn: &Turn) {
    use serde_json::{Map, Value};
    let entity_id = format!("tm:turn/{trail_id}/{i}");
    let mut entity = Map::new();
    entity.insert("@id".to_string(), Value::String(entity_id.clone()));
    entity.insert("@type".to_string(), type_single("prov:Entity"));
    let derived: Vec<Value> = turn
        .parents
        .iter()
        .map(|p| Value::String(p.0.to_hex()))
        .collect();
    if !derived.is_empty() {
        entity.insert("prov:wasDerivedFrom".to_string(), Value::Array(derived));
    }
    if let Some(superseded) = &turn.supersedes {
        entity.insert(
            "tm:supersedes".to_string(),
            Value::String(superseded.0.to_hex()),
        );
    }
    graph.push(Value::Object(entity));

    for (j, entry) in turn.ledger.entries.iter().enumerate() {
        let verb = serde_json::to_value(entry.action)
            .ok()
            .and_then(|v| v.as_str().map(alloc::string::ToString::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        let mut activity = Map::new();
        activity.insert(
            "@id".to_string(),
            Value::String(format!("tm:activity/{trail_id}/{i}/{j}")),
        );
        activity.insert(
            "@type".to_string(),
            type_pair("prov:Activity", &format!("tm:{verb}")),
        );
        activity.insert(
            "prov:wasAssociatedWith".to_string(),
            Value::String(entry.attributed_to.id.clone()),
        );
        if let Ok(t) = serde_json::to_value(entry.attested_at) {
            activity.insert("prov:atTime".to_string(), t);
        }
        if let Some(scope) = entry
            .approval_scope
            .and_then(|s| serde_json::to_value(s).ok())
        {
            activity.insert("tm:approvalScope".to_string(), scope);
        }
        activity.insert(
            "prov:generated".to_string(),
            Value::String(entity_id.clone()),
        );
        graph.push(Value::Object(activity));
    }
}

/// A `{"@id": id, "@type": ty}` node.
fn node_with_type(id: String, ty: serde_json::Value) -> serde_json::Value {
    let mut node = serde_json::Map::new();
    node.insert("@id".to_string(), serde_json::Value::String(id));
    node.insert("@type".to_string(), ty);
    serde_json::Value::Object(node)
}

/// A single-string `@type`.
fn type_single(a: &str) -> serde_json::Value {
    serde_json::Value::String(a.to_string())
}

/// A two-element `@type` array.
fn type_pair(a: &str, b: &str) -> serde_json::Value {
    serde_json::Value::Array(alloc::vec![
        serde_json::Value::String(a.to_string()),
        serde_json::Value::String(b.to_string()),
    ])
}
