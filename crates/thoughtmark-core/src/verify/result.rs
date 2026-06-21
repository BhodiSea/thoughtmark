// SPDX-License-Identifier: Apache-2.0
//! The `verify()` result types (arch §11.3).
//!
//! Every type here is byte-deterministic: integers, enums, constant `&'static str`, and fixed-order `Vec`s only —
//! no `HashMap` iteration, no timestamp other than the injected `now`. The JCS-canonical bytes of a
//! [`VerificationResult`] are exactly what `spec/vectors/verify/*` pins (§13). [`NotEstablished`] is **constant in
//! v1** — the integrity-of-record honesty frame (I7) encoded permanently in the type system.

use crate::canon::Digest;
use crate::determinism::UnixMillis;
use crate::error::ErrorCode;
use crate::scalar::{Action, ParticipantKind};
use alloc::string::String;
use alloc::vec::Vec;

/// The frozen verification-result schema identifier.
pub const VERIFICATION_RESULT_SCHEMA: &str = "thoughtmark.verification_result/v1";

/// The status of a single check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CheckStatus {
    /// The check passed.
    Pass,
    /// The check failed (the [`CheckOutcome::code`] says how).
    Fail,
    /// The check did not apply (neutral in `total`).
    Skipped,
}

/// The kinds of check, in their fixed, byte-stable order (arch §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CheckKind {
    /// The bundle's structural shape (media type / version / canon version).
    BundleSchema,
    /// The bundle's `canon_version` is one the policy accepts.
    CanonVersion,
    /// The DSSE envelope verifies under a trusted key.
    DsseSignature,
    /// The in-toto subject binds the trail (digest / name / tree_size).
    StatementBinding,
    /// The statement leaf is included in the checkpoint's tree.
    MerkleInclusion,
    /// The checkpoint is signed by ≥ `required_witnesses` trusted log keys.
    Checkpoint,
    /// The append-only consistency proof reconciles (skipped if absent).
    Consistency,
    /// An external anchor proves a time upper bound (skipped if `!require_anchor`).
    AnchorReceipt,
    /// The contribution-lineage DAG is well-formed and satisfies the policy.
    ContributionLineage,
}

impl CheckKind {
    /// The fixed emission order of the nine checks. The result's `checks` vec is built against this array so the
    /// output order never depends on internal evaluation order.
    pub const ORDER: [CheckKind; 9] = [
        CheckKind::BundleSchema,
        CheckKind::CanonVersion,
        CheckKind::DsseSignature,
        CheckKind::StatementBinding,
        CheckKind::MerkleInclusion,
        CheckKind::Checkpoint,
        CheckKind::Consistency,
        CheckKind::AnchorReceipt,
        CheckKind::ContributionLineage,
    ];
}

/// Non-sensitive scalar context for a check outcome (arch §11.3: "non-sensitive scalars only").
///
/// Carries only counts, sizes, and frozen tokens — NEVER record or secret bytes (I5/I7). `#[non_exhaustive]` so a
/// future scalar is additive.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CheckDetail {
    /// e.g. the count of signatures / witness cosignatures that verified.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub matched: Option<u32>,
    /// e.g. the required count for a k-of-n threshold.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub required: Option<u32>,
    /// e.g. the `tree_size` bound by the statement / inclusion proof (decimal string).
    #[serde(
        with = "crate::wire::dec_u64_opt",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub tree_size: Option<u64>,
}

impl CheckDetail {
    /// An all-`None` detail (nothing scalar to report).
    #[must_use]
    pub const fn empty() -> CheckDetail {
        CheckDetail {
            matched: None,
            required: None,
            tree_size: None,
        }
    }

    /// True iff every field is `None` (so the orchestrator can omit an empty detail).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matched.is_none() && self.required.is_none() && self.tree_size.is_none()
    }
}

/// The outcome of one check (arch §11.3).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckOutcome {
    /// Which check this is.
    pub kind: CheckKind,
    /// Its status.
    pub status: CheckStatus,
    /// The stable failure code, when `status == Fail`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code: Option<ErrorCode>,
    /// Non-sensitive scalar context, when any is present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<CheckDetail>,
}

/// One step in the contribution lineage (arch §11.3).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageStep {
    /// Whether the contributor is a human or an AI.
    pub participant_kind: ParticipantKind,
    /// The contributor's DID (the attributed-to id; never PII).
    pub participant_id: String,
    /// The action attributed.
    pub action: Action,
    /// The INJECTED attestation time of the contribution.
    pub at: UnixMillis,
}

/// The affirmative claims a passing verification establishes (arch §11.3).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Established {
    /// The tightest UPPER time bound (min over passing anchors). `None` until a real `AnchorVerifier` is injected
    /// (Phase 4) — at 1.0 the time bound cannot be established.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub existed_at_or_before: Option<UnixMillis>,
    /// `DsseSignature && StatementBinding && MerkleInclusion && Checkpoint` all passed.
    pub unaltered_since_capture: bool,
    /// The contribution lineage, populated only when `ContributionLineage` passes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lineage: Option<Vec<LineageStep>>,
    /// The subject digest the statement bound, when `StatementBinding` passes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bound_subject_digest: Option<Digest>,
    /// The signer keyids (DIDs) whose signature verified.
    pub signed_by: Vec<String>,
    /// The log origin, when `Checkpoint` passes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub log_origin: Option<String>,
}

/// The honesty frame's permanent non-claims, exactly the strings of [`NotEstablished`].
pub const NOT_ESTABLISHED_AUTHORSHIP_TRUTH: &str = "Not proven: that the named participant authored the content — only that this key signed this record.";
/// See [`NotEstablished`].
pub const NOT_ESTABLISHED_COMPLETENESS: &str =
    "Not proven: that no off-record turns occurred outside the captured trail.";
/// See [`NotEstablished`].
pub const NOT_ESTABLISHED_FAITHFULNESS: &str =
    "Not proven: that the trail reflects the model's actual internal computation.";
/// See [`NotEstablished`].
pub const NOT_ESTABLISHED_TIME_UPPER_BOUND_ONLY: &str =
    "Anchors prove existence at-or-before T (an upper bound), not exact creation time.";
/// See [`NotEstablished`].
pub const NOT_ESTABLISHED_VALIDITY_OF_RECORD: &str =
    "Not proven: that the reasoning is correct or the answer is right.";

/// The integrity-of-record honesty frame (I7), **constant in v1** — always present, identical bytes for every
/// run. A unit struct whose hand-written `Serialize` always emits the five constant fields (in JCS key order, so
/// canonicalization is a no-op reorder); `&'static str` fields cannot themselves `Deserialize`, so the type is a
/// unit struct and its `Deserialize` accepts the constant object and yields the unit — the bytes are therefore
/// *structurally* constant, the strongest possible I7 guarantee.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotEstablished;

impl serde::Serialize for NotEstablished {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut st = serializer.serialize_struct("NotEstablished", 5)?;
        st.serialize_field("authorship_truth", NOT_ESTABLISHED_AUTHORSHIP_TRUTH)?;
        st.serialize_field("completeness", NOT_ESTABLISHED_COMPLETENESS)?;
        st.serialize_field("faithfulness", NOT_ESTABLISHED_FAITHFULNESS)?;
        st.serialize_field(
            "time_upper_bound_only",
            NOT_ESTABLISHED_TIME_UPPER_BOUND_ONLY,
        )?;
        st.serialize_field("validity_of_record", NOT_ESTABLISHED_VALIDITY_OF_RECORD)?;
        st.end()
    }
}

impl<'de> serde::Deserialize<'de> for NotEstablished {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The block is a v1 constant; accept the object and ignore its contents (we never trust an input's copy
        // of a constant the type system already pins).
        deserializer.deserialize_ignored_any(serde::de::IgnoredAny)?;
        Ok(NotEstablished)
    }
}

/// The full verification verdict + report (arch §11.3). Returned as a VALUE, never `Result`: a tamper is a
/// successful run with `total == false`, so the proven/not-proven report always reaches the caller.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    /// `"thoughtmark.verification_result/v1"`.
    pub schema: String,
    /// The single injected `now` (explains the time checks; reproducible).
    pub verified_at: UnixMillis,
    /// The AND of all REQUIRED (non-`Skipped`) checks.
    pub total: bool,
    /// Every check outcome, in fixed [`CheckKind::ORDER`].
    pub checks: Vec<CheckOutcome>,
    /// The affirmative claims established.
    pub established: Established,
    /// The permanent non-claims (constant in v1).
    pub not_established: NotEstablished,
}
