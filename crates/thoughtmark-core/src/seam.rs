// SPDX-License-Identifier: Apache-2.0
//! Extension-seam traits frozen empty at 1.0 (arch §14.4, §16).
//!
//! The 1.0 freeze cannot freeze types that do not yet exist, so the type *shapes* are declared here even where
//! their behaviour is supplied by a later phase. These seams carry NO implementation in core: the concrete
//! impls live in shell/plugin crates (`thoughtmark-attest-tee`, `thoughtmark-identity`) so their parser/runtime
//! deps stay out of the audited core (I8). Adding a variant to a `#[non_exhaustive]` enum or wiring an impl later
//! is purely additive (MINOR, §16) precisely because the empty seam is already frozen.

use crate::error::Result;
use crate::sign::VerifyingKey;
use alloc::vec::Vec;

/// The family of attestation an [`Attestor`] produces (arch §5.7, §14.4). Empty of behaviour until Phase 7 wires
/// a TEE/zkML impl and populates the predicate's `inference_attestation`. `#[non_exhaustive]` — a new family is a
/// MINOR.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    /// NVIDIA NRAS remote attestation of a TEE.
    TeeNras,
    /// Phala-network TEE attestation.
    TeePhala,
    /// An EZKL zero-knowledge ML proof.
    ZkmlEzkl,
}

/// The attestation seam: produce evidence (a TEE quote, a zkML proof) over a claim. **Empty at 1.0** — no impl
/// ships in core; the concrete `Attestor` (`thoughtmark-attest-tee`) lands in a later phase. Freezing the trait
/// shape now keeps populating `inference_attestation` purely additive (arch §14.4, §16).
pub trait Attestor {
    /// The attestation family this attestor speaks.
    fn kind(&self) -> AttestationKind;

    /// Produce attestation evidence bytes over `claim` (opaque to core).
    ///
    /// # Errors
    /// Returns an [`Err`] if the underlying attestor cannot produce evidence.
    fn attest(&self, claim: &[u8]) -> Result<Vec<u8>>;
}

/// The identity-resolution seam: resolve a DID / verificationMethod URL to its offline key material.
///
/// Declared **sync** because the audited core is `#![no_std]` and never awaits or opens a socket; the async
/// `did:web` resolver wraps this in the effectful shell (`thoughtmark-identity`, arch §3.2, §9). Frozen empty at
/// 1.0 — no impl ships in core.
pub trait IdentityResolver {
    /// Resolve a DID / verificationMethod URL to its verification key.
    ///
    /// # Errors
    /// Returns an [`Err`] if the identifier is unknown or cannot be resolved offline.
    fn resolve(&self, did: &str) -> Result<VerifyingKey>;
}
