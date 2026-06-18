// SPDX-License-Identifier: Apache-2.0
//! The single base64 choke point for the transparency-tree / DSSE wire forms.
//!
//! Encoding rule (arch §7.1, §6.4): **emit STANDARD padded base64 on write, accept BOTH standard and url-safe
//! (padded or not) on read** — a signature is over the underlying bytes, independent of the base64 alphabet, so a
//! verifier must tolerate either. A thin wrapper over the audited `base64` crate keeps one place to swap the impl
//! and stays inside the no-panic wall (`decode_any` returns `Option`, never panics).

use alloc::string::String;
use alloc::vec::Vec;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

/// Encode bytes as STANDARD padded base64.
pub(crate) fn encode_std(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode standard OR url-safe base64 (padded or not), fail-closed to `None` on any malformed input.
pub(crate) fn decode_any(s: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| URL_SAFE.decode(s).ok())
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(s).ok())
}
