// SPDX-License-Identifier: Apache-2.0
//! The contribution ledger (arch §5.5) — the heart of the predicate.
//!
//! A single [`crate::Turn`] carries **≥1** [`LedgerEntry`]; multiple entries give sub-turn multi-party attribution
//! (human `create` → AI `refine` → human `approve`). The field names carry the honesty frame (I7): `attributed_to`
//! (not "author"), `attested_at` (the INJECTED time, not "occurred"). PROV-O is *derived* from this ledger
//! (arch §5.10), never stored separately, so there is one canonicalized source of truth.

use crate::action::{Action, ApprovalScope};
use crate::participant::ParticipantRef;
use alloc::vec::Vec;
use thoughtmark_core::{Digest, UnixMillis};

/// One attributed contribution within a turn.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// The action taken.
    pub action: Action,
    /// The credited participant (a DID) — "attributed", not "author".
    pub attributed_to: ParticipantRef,
    /// The INJECTED time of attestation — "attested", not "occurred".
    pub attested_at: UnixMillis,
    /// For endorsement verbs: the honesty limit of the approval (committed in the hashed bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_scope: Option<ApprovalScope>,
    /// A salted-hash commitment to a free-text note (the note stays off-ledger).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_digest: Option<Digest>,
}

/// The ordered list of contributions for a turn (≥1 entry).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionLedger {
    /// The entries, in attribution order.
    pub entries: Vec<LedgerEntry>,
}
