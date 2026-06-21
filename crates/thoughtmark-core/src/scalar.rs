// SPDX-License-Identifier: Apache-2.0
//! Shared wire scalars relocated into the audited core (arch §5.1, §14.3).
//!
//! These leaf types are part of the frozen §14.3 "core types" surface and are reused by the §11 `verify`
//! pipeline (`Policy::required_actions`, `Policy::accepted_canon_versions`, `LineageStep`). The audited core
//! cannot depend on `thoughtmark-schema` (the dependency points inward, `schema → core`, I8), so the leaf enums
//! `verify` needs live HERE and are **re-exported** from `thoughtmark-schema` to preserve the single-definition
//! rule (§14.3). The serde forms are byte-identical to their former schema definitions — the conformance corpus
//! is the oracle that the relocation changed no wire byte.

/// What a ledger entry asserts about an artifact (arch §5.3).
///
/// The lifecycle/endorsement split (verdict #1) keeps edit-and-regenerate first-class while scoping endorsement
/// honestly. `#[non_exhaustive]` — a new verb is a MINOR (arch §16).
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

/// The honesty *limit* of an approval, committed inside the hashed `LedgerEntry` (arch §5.4, verdict #5).
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

/// Whether a participant is a human or an AI (arch §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantKind {
    /// A human participant.
    Human,
    /// An AI participant.
    Ai,
}

/// The in-toto Statement `_type` (frozen format-identifier value, arch §14.2).
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The thoughtmark provenance `predicateType` (frozen format-identifier value, arch §14.2).
pub const PREDICATE_TYPE: &str = "https://thoughtmark.dev/Provenance/v1";

/// The canonicalization format identifier, as a typed value (arch §5.1, §14.3).
///
/// Serializes as its [`CanonVersion::as_str`] (`"tm-jcs-1"`, identical to [`crate::CANON_VERSION`]).
/// [`CanonVersion::parse`] is fail-closed: an unknown token deserializes to a serde error carrying the
/// `UNKNOWN_CANON_VERSION` code (never best-effort recompute — arch §16). `#[non_exhaustive]` so a future
/// `canon_v2` is a MINOR.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonVersion {
    /// `"tm-jcs-1"` — the v1 RFC 8785 JCS canonicalization.
    TmJcs1,
}

impl CanonVersion {
    /// The stable wire token for this version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CanonVersion::TmJcs1 => "tm-jcs-1",
        }
    }

    /// Parse a wire token, fail-closed (`None` for an unknown version).
    #[must_use]
    pub fn parse(token: &str) -> Option<CanonVersion> {
        match token {
            "tm-jcs-1" => Some(CanonVersion::TmJcs1),
            _ => None,
        }
    }
}

impl serde::Serialize for CanonVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CanonVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = <&str as serde::Deserialize>::deserialize(deserializer)?;
        // Carry the stable ErrorCode token in the serde error so a malformed canon_version stays fail-closed.
        CanonVersion::parse(token).ok_or_else(|| serde::de::Error::custom("UNKNOWN_CANON_VERSION"))
    }
}
