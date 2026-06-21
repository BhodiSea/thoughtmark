// SPDX-License-Identifier: Apache-2.0
//! Turn & Trail (arch §5.8, verdicts #3, #4).
//!
//! Ordering authority is normative (SPEC `LOG-*`): `parents` (the DAG) plus the Merkle-log leaf position are the
//! **sole** ordering authority; `sequence` is a non-authoritative display hint a verifier never relies on. A
//! [`TurnId`] *is* its turn's content digest, so any mutation changes the id — tamper-evidence is intrinsic — and
//! a `TurnId` is therefore never a field inside [`Turn`] (you cannot hash a struct containing its own hash). The
//! derivations live in [`crate::derive`].

use crate::content::ContentPart;
use crate::ledger::ContributionLedger;
use crate::scalar::{CanonVersion, CanonicalValue, SchemaVersion};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use thoughtmark_core::{Digest, UnixMillis};

/// A derived turn identifier: the tagged [`Digest`] of the canonical turn. Never stored inside a [`Turn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct TurnId(pub Digest);

/// The role a turn plays in a trail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    /// A human turn.
    Human,
    /// An AI turn.
    Ai,
    /// A system turn.
    System,
    /// A tool turn.
    Tool,
}

/// A single turn in a reasoning trail.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Turn {
    /// The schema version.
    pub schema_version: SchemaVersion,
    /// The canonicalization version (asserted equal to `CANON_VERSION`, fail-closed).
    pub canon_version: CanonVersion,
    /// A NON-authoritative display hint only (the DAG + leaf position are authoritative).
    pub sequence: u64,
    /// The role of this turn.
    pub role: TurnRole,
    /// The multi-part content (verdict #2).
    pub content: Vec<ContentPart>,
    /// DAG edges — the SOLE topological authority (linear chat = a single parent).
    pub parents: Vec<TurnId>,
    /// A typed edit/regenerate/retract edge (verdict #1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<TurnId>,
    /// The contribution ledger (≥1 entry).
    pub ledger: ContributionLedger,
    /// AI/System/Tool turns MUST set this (the requirement is enforced by `verify()`, a later phase; the schema
    /// keeps it `Option` so the wire form round-trips).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_manifest_ref: Option<Digest>,
    /// Float-free extension data.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub extensions: BTreeMap<String, CanonicalValue>,
}

/// A reasoning trail (a.k.a. `ScholarlyObject`): the ordered set of turns and their head.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trail {
    /// The schema version.
    pub schema_version: SchemaVersion,
    /// The canonicalization version.
    pub canon_version: CanonVersion,
    /// An opaque caller-supplied trail id.
    pub trail_id: String,
    /// The trail's creation attestation time.
    pub created_attested_at: UnixMillis,
    /// The turn ids in canonical (display) order; authority is the DAG + leaf position.
    pub turns: Vec<TurnId>,
    /// The head turn id.
    pub head: TurnId,
    /// Float-free extension data.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub extensions: BTreeMap<String, CanonicalValue>,
}
