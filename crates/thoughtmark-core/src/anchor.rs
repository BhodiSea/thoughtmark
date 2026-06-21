// SPDX-License-Identifier: Apache-2.0
//! The anchor seam — TYPES and TRAIT only (arch §8.2, §8.3, ADR-0008).
//!
//! The bundle's `anchors` field depends on [`AnchorReceipt`] here, so the seam types it names are defined now;
//! the actual anchor parsers/backends (OpenTimestamps / RFC 3161 / Fabric — DER/CMS/Bitcoin-header parsing) and
//! the pure `AnchorVerifier` impl land in a later phase. Core defines no parsing logic and no deps beyond serde:
//! `proof` is **OPAQUE** to core, and the structured fields are advisory caches re-derived at verify time, never
//! trusted. [`verify()`](crate) (a later phase) injects a `&dyn AnchorVerifier`.

use crate::determinism::UnixMillis;
use crate::error::ErrorCode;
use crate::merkle::TreeHash;
use crate::sign::VerifyingKey;
use crate::wire::{bytes_b64, dec_u64};
use alloc::string::String;
use alloc::vec::Vec;

/// The frozen anchor-receipt schema identifier.
pub const ANCHOR_RECEIPT_SCHEMA: &str = "thoughtmark.anchor.receipt/v1";

/// An external timestamping anchor receipt. `proof` is opaque to core.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AnchorReceipt {
    /// `"thoughtmark.anchor.receipt/v1"`.
    pub schema: String,
    /// The anchoring mechanism.
    pub kind: AnchorKind,
    /// The anchoring status.
    pub status: AnchorStatus,
    /// The tree root being anchored.
    pub root: TreeHash,
    /// A reference re-binding the root to its log.
    pub checkpoint_ref: CheckpointRef,
    /// The opaque proof bytes (parsed only by a backend in a later phase).
    #[serde(with = "bytes_b64")]
    pub proof: Vec<u8>,
}

/// The anchoring mechanism. `#[non_exhaustive]` — adding a variant is a MINOR.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// OpenTimestamps (Bitcoin calendar).
    OpenTimestamps,
    /// RFC 3161 Time-Stamp Protocol.
    Rfc3161,
    /// A Fabric/notary anchor.
    Fabric,
}

/// The anchoring status.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AnchorStatus {
    /// Submitted, not yet anchored; pending in these calendars.
    Pending {
        /// Calendar URIs to poll.
        calendar_uris: Vec<String>,
    },
    /// Anchored, with a lower-bound time if known.
    Anchored {
        /// A proven lower-bound timestamp, if established.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        time_lower_bound: Option<UnixMillis>,
    },
}

/// A reference re-binding a `root` to its log (origin + size + signer key id).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRef {
    /// The log origin.
    pub origin: String,
    /// The tree size.
    #[serde(with = "dec_u64")]
    pub tree_size: u64,
    /// The checkpoint signer's key id.
    pub signer_keyid: String,
}

/// The verdict an [`AnchorVerifier`] returns (a runtime result, not a wire type).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// Anchored with a proven lower-bound time.
    Valid {
        /// The proven lower-bound time.
        time_lower_bound: UnixMillis,
        /// The mechanism that proved it.
        source: AnchorKind,
    },
    /// Not yet anchored.
    Pending,
    /// Invalid, with the reason code.
    Invalid(ErrorCode),
}

/// Borrowed trust inputs an [`AnchorVerifier`] needs (no fetching — everything is supplied). Parser-bearing
/// fields (X.509 roots, block-header oracles) live in the backend crate, not core.
pub struct VerifyParams<'a> {
    /// Keys trusted to sign checkpoints the receipt references.
    pub trusted_keys: &'a [VerifyingKey],
}

/// The verifier seam. The concrete (pure) impl ships in a later phase; [`verify()`](crate::verify) injects a
/// `&dyn AnchorVerifier`.
pub trait AnchorVerifier {
    /// Verify a receipt against the checkpoint it anchors.
    fn verify_anchor(
        &self,
        checkpoint_bytes: &[u8],
        receipt: &AnchorReceipt,
        params: &VerifyParams<'_>,
    ) -> AnchorVerdict;
}

/// The Phase-3 default [`AnchorVerifier`]: core ships NO anchor parsers (the DER/CMS/OTS/Bitcoin-header backends
/// live in `thoughtmark-anchor`, delivered in Phase 4, ADR-0008). Every receipt is therefore rejected with
/// [`ErrorCode::AnchorUnsupportedKind`], so a `Policy::require_anchor = true` run fails the `AnchorReceipt` check
/// honestly and `Established::existed_at_or_before` stays `None` — the `time_upper_bound_only` honesty note holds
/// until a real verifier is injected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoAnchorVerifier;

impl AnchorVerifier for NoAnchorVerifier {
    fn verify_anchor(
        &self,
        _checkpoint_bytes: &[u8],
        _receipt: &AnchorReceipt,
        _params: &VerifyParams<'_>,
    ) -> AnchorVerdict {
        AnchorVerdict::Invalid(ErrorCode::AnchorUnsupportedKind)
    }
}
