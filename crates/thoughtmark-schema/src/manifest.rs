// SPDX-License-Identifier: Apache-2.0
//! The AI run manifest, bound per turn (arch §5.7).
//!
//! Model identity is cryptographically attached to every AI turn: the manifest's own id is
//! `hash_domain(alg, MANIFEST, canonicalize(rm))` (its dedicated domain, arch §4.5), referenced from the turn via
//! `run_manifest_ref`. `temperature`/`top_p` are carried as fixed-point `*_milli: u32` — never `f64` (I4) — the
//! single most important defense against a byte-identity break in this domain. The `seed` is a decimal **string**
//! so it may exceed 2^53. Every field is `model_self_reported` in spirit (I7).

use crate::content::ToolRef;
use crate::scalar::{CanonVersion, CanonicalValue};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use thoughtmark_core::Digest;

/// Decoding parameters, in fixed-point integer form (never floats).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodingParams {
    /// `round(temperature * 1000)` — NEVER an `f64` (I4).
    pub temperature_milli: u32,
    /// `round(top_p * 1000)`.
    pub top_p_milli: u32,
    /// An optional output-token cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
}

/// A reserved reference to an inference attestation (Tier-3; empty until a later phase).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRef {
    /// The TEE/attestor family (e.g. `"tdx"`, `"sev-snp"`, `"nras"`, `"ezkl"`).
    pub tee: String,
    /// A CID for the evidence blob.
    pub evidence_cid: String,
}

/// The manifest describing the AI run that produced a turn.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    /// The canonicalization version (`"tm-jcs-1"`).
    pub canon_version: CanonVersion,
    /// The provider (e.g. `"anthropic"`).
    pub provider: String,
    /// The model id (e.g. `"claude-opus-4-8"`).
    pub model_id: String,
    /// The vendor-reported model version; the name encodes provenance (self-reported, I7).
    pub model_self_reported_version: String,
    /// Decoding parameters.
    pub decoding: DecodingParams,
    /// A salted commitment to the system prompt — proves WHICH prompt without storing it.
    pub system_prompt_digest: Digest,
    /// Tools AVAILABLE to the run (vs an invoked `ToolCall`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tools: Vec<ToolRef>,
    /// An optional context-window size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    /// An optional decoding seed, as a decimal STRING (may exceed 2^53).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    /// A reserved inference-attestation reference (empty until a later phase).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_attestation: Option<AttestationRef>,
    /// Float-free provider-specific parameters.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub provider_params: BTreeMap<String, CanonicalValue>,
}
