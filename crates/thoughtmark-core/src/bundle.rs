// SPDX-License-Identifier: Apache-2.0
//! The `ThoughtmarkBundle` self-verifying offline container (arch §7.6, §11).
//!
//! This is the ONE bundle definition; [`verify()`](crate) (a later phase) consumes it. Phase 2 defines the type +
//! (de)serialization + structural validators only — the cryptographic pipeline (replaying the inclusion proof,
//! the checkpoint signature, and the DSSE envelope) is `verify()`, which is NOT built here. The `ContributionLedger`
//! lives INSIDE the signed `predicate`/`Trail` (the DSSE `envelope.payload`), never as a top-level bundle field.

use crate::anchor::AnchorReceipt;
use crate::dsse::DsseEnvelope;
use crate::error::{Error, ErrorCode};
use crate::merkle::{ConsistencyProof, InclusionProof};
use crate::wire::{bytes_b64, bytes_b64_vec};
use alloc::string::String;
use alloc::vec::Vec;

/// The frozen bundle media type (a freeze-gate value).
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.thoughtmark.bundle.v1+json";
/// The bundle schema version this build understands.
pub const BUNDLE_VERSION: u16 = 1;

/// A self-verifying offline provenance bundle.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThoughtmarkBundle {
    /// `"application/vnd.thoughtmark.bundle.v1+json"`.
    pub media_type: String,
    /// The bundle schema version (gate → `BundleVersionUnsupported`).
    pub bundle_version: u16,
    /// The canonicalization version (must equal the predicate's → `UnknownCanonVersion`).
    pub canon_version: String,
    /// The DSSE-wrapped in-toto Statement (the `Trail` + `ContributionLedger` live inside this signed payload).
    pub envelope: DsseEnvelope,
    /// Keys / stapled DID docs to resolve each `keyid` OFFLINE.
    pub verification_material: VerificationMaterial,
    /// The Merkle inclusion proof for the statement's leaf.
    pub inclusion: InclusionProof,
    /// The C2SP signed-note checkpoint bytes.
    #[serde(with = "bytes_b64")]
    pub checkpoint: Vec<u8>,
    /// An optional consistency proof from a prior checkpoint.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub consistency: Option<ConsistencyProof>,
    /// External anchor receipts (empty until a later phase populates them).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub anchors: Vec<AnchorReceipt>,
    /// The canonical JCS bytes of each `Turn` the predicate `Trail` references by id, stapled so `verify` (§11)
    /// can replay the contribution-lineage DAG offline: it recomputes each `turn_id = hash_domain(BLAKE3, TURN,
    /// body)` and walks `parents`/`supersedes`/the ledger. **Raw bytes, not the typed `Turn`** — the audited core
    /// cannot depend on `thoughtmark-schema` (I8); `verify` parses each body as JSON. A legitimate `Trail` always
    /// declares ≥1 turn, so every declared turn's body MUST be stapled here: the `ContributionLineage` check is
    /// mandatory and fails `LEDGER_BROKEN_LINK` for any declared turn with no stapled body (a body-less bundle
    /// cannot reach `total:true`). The `skip_serializing_if`/`default` is for wire-minimality of the empty case
    /// only (a malformed body-less bundle), never a supported "head-only" shape.
    #[serde(with = "bytes_b64_vec", skip_serializing_if = "Vec::is_empty", default)]
    pub turn_bodies: Vec<Vec<u8>>,
    /// The canonical JCS bytes of each `RunManifest` a stapled turn references via `run_manifest_ref`, so `verify`
    /// can match `hash_domain(BLAKE3, MANIFEST, body)` against the ref. Raw bytes (see `turn_bodies`).
    #[serde(with = "bytes_b64_vec", skip_serializing_if = "Vec::is_empty", default)]
    pub run_manifests: Vec<Vec<u8>>,
}

/// Offline key-resolution material.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationMaterial {
    /// The verification methods (keyid → public key).
    pub verification_methods: Vec<VerificationMethod>,
}

/// One verification method: a key id resolvable offline to a public key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationMethod {
    /// The key id (a DID verificationMethod URL; the DSSE `keyid`).
    pub id: String,
    /// The public key as multibase (e.g. a `did:key` z-base58btc), resolvable without a network.
    pub public_key_multibase: String,
}

impl ThoughtmarkBundle {
    /// Structural validation only (the freeze-gate shape). The cryptographic pipeline is `verify()`, a later phase.
    ///
    /// # Errors
    /// `BundleSchemaInvalid` for a wrong media type; `BundleVersionUnsupported` for an unknown version;
    /// `UnknownCanonVersion` for a canon version this build does not understand.
    pub fn validate_shape(&self) -> Result<(), Error> {
        if self.media_type != BUNDLE_MEDIA_TYPE {
            return Err(Error::Bundle(ErrorCode::BundleSchemaInvalid));
        }
        if self.bundle_version != BUNDLE_VERSION {
            return Err(Error::Bundle(ErrorCode::BundleVersionUnsupported));
        }
        if self.canon_version != crate::CANON_VERSION {
            return Err(Error::Canon(ErrorCode::UnknownCanonVersion));
        }
        Ok(())
    }
}
