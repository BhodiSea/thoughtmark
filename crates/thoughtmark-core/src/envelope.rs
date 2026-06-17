// SPDX-License-Identifier: Apache-2.0
//! The canonical conformance error envelope (SPEC.md §4).
//!
//! Hand-encoded (not via `serde_json`) so it builds under `no_std` + `alloc` without pulling a JSON serializer
//! onto the WASM path, and so the produced bytes are unambiguous and float-free (I4). The envelope is the
//! Phase-0 stand-in for real output: each implementation independently produces these bytes, and the
//! conformance runner asserts byte-equality across Rust ⟷ WASM/TS (CORE-1/CORE-2).

use crate::error::ErrorCode;
use alloc::vec::Vec;

/// Encode an [`ErrorCode`] as the canonical envelope bytes:
/// `{"ok":false,"error":{"code":"<CODE>"}}` — UTF-8, members in fixed order, no trailing newline, no floats.
#[must_use]
pub fn error_envelope(code: ErrorCode) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(br#"{"ok":false,"error":{"code":""#);
    out.extend_from_slice(code.as_str().as_bytes());
    out.extend_from_slice(br#""}}"#);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_implemented_envelope_is_exact() {
        let bytes = error_envelope(ErrorCode::NotImplemented);
        assert_eq!(bytes, br#"{"ok":false,"error":{"code":"NOT_IMPLEMENTED"}}"#);
    }
}
