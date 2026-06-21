// SPDX-License-Identifier: Apache-2.0
//! The pure, offline `did:key` decoder (arch §7.5, ADR-0010).
//!
//! Vendored into core (~60 LOC) because it is on the byte-identity-critical path; `did:web`/VC resolution stays
//! out until a later phase. Decoding is fail-closed at every step: a wrong prefix, a non-`z` multibase, a
//! non-Ed25519 multicodec, the wrong length, or an off-curve key all return `SigMalformedKey` (never a silently
//! unusable key). `strip_prefix` is used throughout so no `str` slicing is needed (honoring `string_slice`).

use crate::error::{Error, ErrorCode};
use crate::sign::VerifyingKey;
use alloc::string::String;
use alloc::vec::Vec;

/// The Ed25519 multicodec varint prefix (`0xed 0x01`).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Decode a `did:key:z…` Ed25519 DID into a [`VerifyingKey`], fully offline.
///
/// # Errors
/// `SigMalformedKey` for any malformed/short/off-curve input.
pub fn decode_did_key(did: &str) -> Result<VerifyingKey, Error> {
    let malformed = || Error::Signature(ErrorCode::SigMalformedKey);
    let rest = did.strip_prefix("did:key:").ok_or_else(malformed)?;
    let b58 = rest.strip_prefix('z').ok_or_else(malformed)?;
    let raw = bs58::decode(b58).into_vec().map_err(|_| malformed())?;
    let mut bytes = raw.iter().copied();
    if bytes.next() != Some(ED25519_MULTICODEC[0]) || bytes.next() != Some(ED25519_MULTICODEC[1]) {
        return Err(malformed());
    }
    let key: Vec<u8> = bytes.collect();
    let arr = <[u8; 32]>::try_from(key.as_slice()).map_err(|_| malformed())?;
    VerifyingKey::from_bytes(&arr)
}

/// Encode a [`VerifyingKey`] as a `did:key:z…` Ed25519 DID.
#[must_use]
pub fn encode_did_key(vk: &VerifyingKey) -> String {
    let mut multikey = Vec::with_capacity(34);
    multikey.extend_from_slice(&ED25519_MULTICODEC);
    multikey.extend_from_slice(&vk.to_bytes());
    let mut out = String::from("did:key:z");
    out.push_str(&bs58::encode(&multikey).into_string());
    out
}
