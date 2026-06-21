// SPDX-License-Identifier: Apache-2.0
//! in-toto Statement wrapping (arch §5.9; signing detail in arch §7).
//!
//! `tree_size` is bound into `subject.name` (`trail:<trail_id>@<N>`, verdict #4): each Statement attests a
//! **prefix at size N**, not the evolving trail. Every appended turn changes `trail_root`, so the prefix framing
//! is the honest one and lets verifiers chain consistency proofs across snapshots. The `digest` map is dual
//! (`{blake3, sha256}`) for SHA-256-only verifiers.

use crate::turn::Trail;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// The in-toto Statement `_type` (frozen).
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The thoughtmark provenance `predicateType` (frozen freeze-gate value).
pub const PREDICATE_TYPE: &str = "https://thoughtmark.dev/Provenance/v1";

/// An in-toto v1 Statement whose predicate is a [`Trail`] prefix.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    /// `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub type_: String,
    /// The subjects attested (each a trail prefix at a tree size).
    pub subject: Vec<ResourceDescriptor>,
    /// `"https://thoughtmark.dev/Provenance/v1"`.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The Trail IS the predicate.
    pub predicate: Trail,
}

/// A subject descriptor: a trail prefix bound to its `tree_size` and dual digest.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDescriptor {
    /// `"trail:<trail_id>@<tree_size>"` — binds the prefix size (verdict #4).
    pub name: String,
    /// The dual `{"blake3":hex,"sha256":hex}` lowercase-hex digest map.
    pub digest: BTreeMap<String, String>,
}
