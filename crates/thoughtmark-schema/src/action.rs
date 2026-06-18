// SPDX-License-Identifier: Apache-2.0
//! Actions and approval scope (arch §5.3, §5.4).
//!
//! The lifecycle/endorsement split (verdict #1) keeps edit-and-regenerate first-class while scoping endorsement
//! honestly. [`ApprovalScope`] (verdict #5) is recorded *in the hashed `LedgerEntry`*, so the *limit* of an
//! approval is cryptographically committed — a consumer can no longer infer "human verified correctness" from a
//! bare `[ai create, human approve]` sequence. Both enums are `#[non_exhaustive]` (new verbs are a MINOR, arch §16).

/// What a ledger entry asserts about an artifact.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    // ── lifecycle verbs (how the artifact came to be) ──
    /// First authorship of the content.
    Create,
    /// A refinement of prior content.
    Refine,
    /// A proposal for consideration.
    Propose,
    /// A typed edit of a superseded turn.
    Edit,
    /// A regeneration of a superseded turn.
    Regenerate,
    /// A retraction of a prior turn.
    Retract,
    // ── endorsement verbs (a stance ON an artifact, NOT a correctness claim) ──
    /// A review stance (semantics deliberately under-specified in v1).
    Review,
    /// An approval stance, scoped by [`ApprovalScope`].
    Approve,
    /// A rejection stance.
    Reject,
}

/// The honesty *limit* of an approval, committed inside the hashed `LedgerEntry`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// The approver reviewed the artifact.
    Reviewed,
    /// The approver endorses the artifact (reads strongly, but only as a recorded stance).
    Endorsed,
    /// The approver acknowledges the artifact.
    Acknowledged,
    /// No correctness or endorsement claim is made.
    NoClaim,
}
