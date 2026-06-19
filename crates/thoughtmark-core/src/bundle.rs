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
use crate::wire::bytes_b64;
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
