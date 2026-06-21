// SPDX-License-Identifier: Apache-2.0
//! The verification policy (arch §11.1).
//!
//! [`Policy`] is the **runtime** shape `verify()` consumes — it holds resolved [`VerifyingKey`]s, which carry no
//! serde (a public key is validated on-curve at construction, not deserialized). [`PolicyWire`] is the
//! **deserialize-only** op-input shape: keys arrive as `did:key`/hex strings and are resolved through the same
//! choke point the DSSE ops use ([`crate::ops::resolve_key`]). This documented wire/runtime split mirrors the
//! §14.6 boundary mapping (TS `verify` takes key material as data, not trait objects).

use crate::canon::Digest;
use crate::error::Error;
use crate::scalar::{Action, CanonVersion};
use crate::sign::VerifyingKey;
use alloc::string::String;
use alloc::vec::Vec;

/// The caller's verification assertions (runtime form). Holds resolved [`VerifyingKey`]s.
pub struct Policy {
    /// Bind the subject to a known artifact hash, if supplied.
    pub expected_subject_digest: Option<Digest>,
    /// The signer allowlist for the DSSE envelope.
    pub trusted_keys: Vec<VerifyingKey>,
    /// The expected checkpoint origin, if supplied.
    pub log_origin: Option<String>,
    /// The checkpoint signer allowlist.
    pub trusted_log_keys: Vec<VerifyingKey>,
    /// The k-of-n witness cosignature floor (`0` = none beyond the mandatory single log signer).
    pub required_witnesses: u8,
    /// If `true`, ≥1 valid anchor is required.
    pub require_anchor: bool,
    /// The tolerated clock skew for anchor time bounds.
    pub max_clock_skew_ms: i64,
    /// Actions that MUST be present in the lineage (e.g. an AI `create` + a human `approve`).
    pub required_actions: Option<Vec<Action>>,
    /// The canon versions this verifier accepts (fail-closed on others).
    pub accepted_canon_versions: Vec<CanonVersion>,
}

/// The deserialize-only op-input form of [`Policy`]: keys as `did:key`/hex strings, resolved by
/// [`PolicyWire::into_policy`].
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWire {
    /// See [`Policy::expected_subject_digest`].
    #[serde(default)]
    pub expected_subject_digest: Option<Digest>,
    /// `did:key:z…` or 64-hex signer keys.
    #[serde(default)]
    pub trusted_keys: Vec<String>,
    /// See [`Policy::log_origin`].
    #[serde(default)]
    pub log_origin: Option<String>,
    /// `did:key:z…` or 64-hex checkpoint signer keys.
    #[serde(default)]
    pub trusted_log_keys: Vec<String>,
    /// See [`Policy::required_witnesses`].
    pub required_witnesses: u8,
    /// See [`Policy::require_anchor`].
    pub require_anchor: bool,
    /// See [`Policy::max_clock_skew_ms`].
    pub max_clock_skew_ms: i64,
    /// See [`Policy::required_actions`].
    #[serde(default)]
    pub required_actions: Option<Vec<Action>>,
    /// See [`Policy::accepted_canon_versions`].
    pub accepted_canon_versions: Vec<CanonVersion>,
}

impl PolicyWire {
    /// Resolve the key strings into a runtime [`Policy`].
    ///
    /// # Errors
    /// `SigMalformedKey` if any key string is not a valid `did:key`/hex Ed25519 key.
    pub fn into_policy(self) -> Result<Policy, Error> {
        let trusted_keys = resolve_all(&self.trusted_keys)?;
        let trusted_log_keys = resolve_all(&self.trusted_log_keys)?;
        Ok(Policy {
            expected_subject_digest: self.expected_subject_digest,
            trusted_keys,
            log_origin: self.log_origin,
            trusted_log_keys,
            required_witnesses: self.required_witnesses,
            require_anchor: self.require_anchor,
            max_clock_skew_ms: self.max_clock_skew_ms,
            required_actions: self.required_actions,
            accepted_canon_versions: self.accepted_canon_versions,
        })
    }
}

/// Resolve every key string through the DSSE key-resolution choke point.
fn resolve_all(keys: &[String]) -> Result<Vec<VerifyingKey>, Error> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        out.push(crate::ops::resolve_key(key)?);
    }
    Ok(out)
}
