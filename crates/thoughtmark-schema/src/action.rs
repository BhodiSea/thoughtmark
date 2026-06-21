// SPDX-License-Identifier: Apache-2.0
//! Actions and approval scope (arch §5.3, §5.4).
//!
//! The lifecycle/endorsement split (verdict #1) keeps edit-and-regenerate first-class while scoping endorsement
//! honestly. [`ApprovalScope`] (verdict #5) is recorded *in the hashed `LedgerEntry`*, so the *limit* of an
//! approval is cryptographically committed — a consumer can no longer infer "human verified correctness" from a
//! bare `[ai create, human approve]` sequence. Both enums are `#[non_exhaustive]` (new verbs are a MINOR, arch §16).
//!
//! These leaf enums are **defined in [`thoughtmark_core::scalar`]** (the §14.3 core-types surface, reused by the
//! §11 `verify` pipeline which cannot depend on this crate) and re-exported here so every `thoughtmark_schema`
//! path keeps resolving (single definition, §14.3).

pub use thoughtmark_core::{Action, ApprovalScope};
