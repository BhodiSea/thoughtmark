// SPDX-License-Identifier: Apache-2.0
//! Participant & identity (arch §5.2).
//!
//! Humans and AI are co-equal participants keyed by **DID** (`id` is a verificationMethod-resolvable DID URL,
//! NEVER PII). The honesty frame (I7) is in the field name: `model_self_reported_version` encodes "reported, not
//! third-party-attested". A [`ParticipantRef`] inside a ledger entry becomes the DSSE `keyid` (arch §7).

use alloc::string::String;
use thoughtmark_core::Digest;

/// Whether a participant is a human or an AI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantKind {
    /// A human participant.
    Human,
    /// An AI participant.
    Ai,
}

/// A participant in a reasoning trail, identified by a DID.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    /// Human or AI.
    pub kind: ParticipantKind,
    /// A verificationMethod-resolvable DID URL (did:key offline, did:web institutional). NEVER PII.
    pub id: String,
    /// AI only: the model's SELF-REPORTED version; the field name encodes "reported, not attested" (arch §9, I7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_self_reported_version: Option<String>,
    /// An optional role label (e.g. `"investigator"`, `"assistant"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// An optional W3C Verifiable Credential binding, BY DIGEST (the VC stays off-ledger, crypto-shreddable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vc_ref: Option<Digest>,
}

/// A reference to the credited participant inside a [`crate::LedgerEntry`]; its `id` becomes the DSSE `keyid`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantRef {
    /// A DID verificationMethod URL.
    pub id: String,
}
