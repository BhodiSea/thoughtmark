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
//! `thoughtmark-schema` — the reasoning-trail wire types.
//!
//! `#![no_std]` + `alloc`, kept separate from `thoughtmark-core` so the audited core is one trust unit while the
//! serde wire surface evolves independently (ADR-0002). Phase 0 is a placeholder; the `Trail`/`Turn`/
//! `ContentPart`/`ContributionLedger`/`RunManifest` structs land in Phase 1.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// The schema format version targeted by this crate. Baked into hashed bytes is a separate format identifier
/// (arch P4); this constant tracks the wire-struct shape, not the on-ledger format.
pub const SCHEMA_VERSION: u32 = 0;
