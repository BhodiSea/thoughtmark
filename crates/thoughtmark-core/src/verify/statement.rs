// SPDX-License-Identifier: Apache-2.0
//! Deserialize-only views of the signed in-toto `Statement`/`Trail` and the stapled `Turn`/ledger bodies.
//!
//! The audited core cannot import the composite `thoughtmark-schema` wire types (I8), so `verify` reads the
//! fields it needs through these **lenient** local views (unknown fields are ignored — the integrity check is the
//! `turn_id` recompute over the exact stapled bytes, not field-set strictness). The leaf enums [`Action`] and the
//! time [`UnixMillis`]/[`Digest`] scalars ARE the core types, so the views reuse them (no second definition,
//! §14.3). [`StatementView::predicate`] is kept as a raw [`serde_json::Value`] so `StatementBinding` can
//! canonicalize the exact predicate bytes for the `trail_root` recompute.

use crate::canon::Digest;
use crate::determinism::UnixMillis;
use crate::scalar::Action;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// A lenient view of the DSSE-signed in-toto Statement.
#[derive(serde::Deserialize)]
pub(crate) struct StatementView {
    /// `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub type_: String,
    /// The attested subjects (each a trail prefix at a tree size).
    pub subject: Vec<SubjectView>,
    /// `"https://thoughtmark.dev/Provenance/v1"`.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The Trail predicate, kept RAW so `StatementBinding` canonicalizes the exact bytes.
    pub predicate: serde_json::Value,
}

/// A subject descriptor view: `{name, digest:{blake3,sha256}}`.
#[derive(serde::Deserialize)]
pub(crate) struct SubjectView {
    /// `"trail:<trail_id>@<tree_size>"`.
    pub name: String,
    /// The dual `{"blake3":hex,"sha256":hex}` digest map.
    pub digest: BTreeMap<String, String>,
}

/// A lenient view of the Trail predicate (only the lineage-relevant fields).
#[derive(serde::Deserialize)]
pub(crate) struct TrailView {
    /// The turn ids in canonical order (each `TurnId` is `transparent` over a [`Digest`]).
    pub turns: Vec<Digest>,
    /// The head turn id.
    pub head: Digest,
}

/// A lenient view of a stapled `Turn` body (only the DAG/ledger fields `verify` walks).
#[derive(serde::Deserialize)]
pub(crate) struct TurnView {
    /// `"human" | "ai" | "system" | "tool"` — mapped to a [`crate::ParticipantKind`] for the lineage step.
    pub role: String,
    /// The DAG parent edges.
    #[serde(default)]
    pub parents: Vec<Digest>,
    /// The optional typed edit/regenerate/retract edge.
    #[serde(default)]
    pub supersedes: Option<Digest>,
    /// The contribution ledger (≥1 entry).
    pub ledger: LedgerView,
    /// The optional AI run-manifest reference.
    #[serde(default)]
    pub run_manifest_ref: Option<Digest>,
}

/// A lenient view of a turn's contribution ledger.
#[derive(serde::Deserialize)]
pub(crate) struct LedgerView {
    /// The entries, in attribution order.
    pub entries: Vec<EntryView>,
}

/// A lenient view of one ledger entry (action + attributed DID + attested time).
#[derive(serde::Deserialize)]
pub(crate) struct EntryView {
    /// The action attributed.
    pub action: Action,
    /// The credited participant (a DID).
    pub attributed_to: ParticipantRefView,
    /// The INJECTED attestation time.
    pub attested_at: UnixMillis,
}

/// A lenient view of an entry's attributed-to reference (its `id` is a DID).
#[derive(serde::Deserialize)]
pub(crate) struct ParticipantRefView {
    /// A DID verificationMethod URL.
    pub id: String,
}
