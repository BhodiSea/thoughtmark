// SPDX-License-Identifier: Apache-2.0
//! DSSE — the Dead Simple Signing Envelope (arch §7.1, §7.2).
//!
//! The signature is over the **Pre-Authentication Encoding** (PAE), not the envelope, so the base64 alphabet of
//! `payload`/`sig` is irrelevant to validity: emit STANDARD padded base64 on write, accept either on read. The
//! payload type is the frozen freeze-gate value [`DSSE_PAYLOAD_TYPE`]. `LEN` is rendered with `itoa`
//! (allocation-free, no leading zeros) — never `format!`, whose locale/width behavior could drift a byte.

use alloc::string::String;
use alloc::vec::Vec;

/// The frozen DSSE payload type for thoughtmark Statements.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` (SP = `0x20`; `body` = raw JCS bytes,
/// NOT base64). This is exactly the byte string Ed25519 signs.
#[must_use]
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut type_len = itoa::Buffer::new();
    let mut body_len = itoa::Buffer::new();
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1");
    out.push(0x20);
    out.extend_from_slice(type_len.format(payload_type.len()).as_bytes());
    out.push(0x20);
    out.extend_from_slice(payload_type.as_bytes());
    out.push(0x20);
    out.extend_from_slice(body_len.format(body.len()).as_bytes());
    out.push(0x20);
    out.extend_from_slice(body);
    out
}

/// A DSSE envelope: a base64 `payload`, its `payloadType`, and the detached signatures over the PAE.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    /// STANDARD-padded base64 of the raw payload (the canonical Statement bytes).
    pub payload: String,
    /// The payload type (`application/vnd.in-toto+json`).
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// The signatures (exactly one per sealed turn, ADR-0007).
    pub signatures: Vec<EnvSig>,
}

/// One DSSE signature: the signer key id and the base64 signature bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSig {
    /// The signer's key id (a DID verificationMethod URL).
    pub keyid: String,
    /// STANDARD-padded base64 of the 64-byte Ed25519 signature.
    pub sig: String,
}
