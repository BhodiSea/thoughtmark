// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    clippy::todo,
    clippy::float_arithmetic,
    clippy::string_slice
)]
//! `thoughtmark-schema` — the reasoning-trail wire types (`Provenance/v1`).
//!
//! `#![no_std]` + `alloc`, kept a separate crate from `thoughtmark-core` so the audited core is one trust unit
//! while the serde wire surface evolves (ADR-0002). It depends INWARD on `thoughtmark-core` (the
//! dependency-direction invariant, I8): it embeds the audited wire scalars [`Digest`]/[`HashAlg`]/[`UnixMillis`]
//! and routes its derivations through the single `canon::jcs` choke point — it hashes nothing of its own.
//!
//! Every wire struct is `#[serde(deny_unknown_fields)]` (fail-closed) and uses `skip_serializing_if` so an absent
//! field is distinct from `null` and `[]`. The determinism-critical forms — `Digest` as `{"alg","bytes_hex"}`,
//! `UnixMillis`/`seed` as decimal strings, `*_milli` integers, NO `salt_hex` on-ledger — make the canonical bytes
//! byte-identical across Rust/WASM/TS (the wire-format freeze, arch §5, §16).

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod action;
pub mod content;
pub mod derive;
pub mod ledger;
pub mod manifest;
pub mod participant;
pub mod scalar;
pub mod statement;
pub mod turn;

// The audited wire scalars live in `thoughtmark-core` (the byte-identity-critical surface); re-export them so
// downstream code can name them via the schema crate without reaching past it.
pub use thoughtmark_core::{Digest, HashAlg, UnixMillis};

pub use action::{Action, ApprovalScope};
pub use content::{ContentDigest, ContentPart, ToolRef};
pub use derive::{export_prov, manifest_id, trail_root, turn_id};
pub use ledger::{ContributionLedger, LedgerEntry};
pub use manifest::{AttestationRef, DecodingParams, RunManifest};
pub use participant::{Participant, ParticipantKind, ParticipantRef};
pub use scalar::{CanonVersion, CanonicalValue, SchemaVersion};
pub use statement::{PREDICATE_TYPE, ResourceDescriptor, STATEMENT_TYPE, Statement};
pub use turn::{Trail, Turn, TurnId, TurnRole};

/// The schema format version targeted by this crate. The on-ledger format identifier baked into hashed bytes is
/// separate (`canon_version = "tm-jcs-1"`, arch P4); this constant tracks the wire-struct shape (now Phase-2 v1).
pub const SCHEMA_VERSION: u32 = 1;
