// SPDX-License-Identifier: Apache-2.0
//! The canonical error envelope.
//!
//! Hand-encoded (not via `serde_json`) so it builds under `no_std` + `alloc` without pulling a JSON serializer
//! onto the WASM path, and so the produced bytes are unambiguous and float-free (I4). On error, [`crate::ops`]
//! returns these bytes; the SCREAMING_SNAKE_CASE code embedded here is the token negative vectors assert on, and
//! it is byte-identical across Rust, WASM, and the pure-TS executors.

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
    fn float_envelope_is_exact() {
        let bytes = error_envelope(ErrorCode::CanonNonDeterministicFloat);
        assert_eq!(
            bytes,
            br#"{"ok":false,"error":{"code":"CANON_NON_DETERMINISTIC_FLOAT"}}"#
        );
    }
}
