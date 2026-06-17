// SPDX-License-Identifier: Apache-2.0
//! Minimal `no_std` lowercase hex encode/decode.
//!
//! Hand-written rather than pulling the `hex` crate so the exact decode path stays inside the no-panic wall and
//! the audited dependency closure stays minimal. Every operation avoids indexing, raw arithmetic, and string
//! slicing (`clippy::indexing_slicing` / `arithmetic_side_effects` / `string_slice` are denied).

use alloc::string::String;
use alloc::vec::Vec;

/// The lowercase hex digit for a nibble `n` in `0..=15`. Any other value is unreachable by construction (callers
/// always pass a masked/shifted nibble); it maps to `'0'` rather than panicking (`.get` avoids indexing).
fn nibble_char(n: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match HEX.get(n as usize) {
        Some(&b) => b as char,
        None => '0',
    }
}

/// The numeric value `0..=15` of a lowercase hex digit byte, or `None` if it is not a lowercase hex digit.
const fn hex_val(c: u8) -> Option<u8> {
    Some(match c {
        b'0' => 0,
        b'1' => 1,
        b'2' => 2,
        b'3' => 3,
        b'4' => 4,
        b'5' => 5,
        b'6' => 6,
        b'7' => 7,
        b'8' => 8,
        b'9' => 9,
        b'a' => 10,
        b'b' => 11,
        b'c' => 12,
        b'd' => 13,
        b'e' => 14,
        b'f' => 15,
        _ => return None,
    })
}

/// Encode bytes as a lowercase hex string (two chars per byte).
#[must_use]
pub(crate) fn encode_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(nibble_char(b.wrapping_shr(4)));
        out.push(nibble_char(b & 0x0f));
    }
    out
}

/// Decode a lowercase hex string to bytes. Returns `None` on odd length or any non-`[0-9a-f]` byte (fail-closed;
/// uppercase is rejected so the wire form is unambiguous).
#[must_use]
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len().wrapping_div(2));
    for pair in bytes.chunks_exact(2) {
        let (hi, lo) = match pair {
            [hi, lo] => (hex_val(*hi)?, hex_val(*lo)?),
            // `chunks_exact(2)` only yields length-2 slices; this arm is unreachable.
            _ => return None,
        };
        out.push(hi.wrapping_shl(4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_lowercase() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff, 0x10];
        let hex = encode_lower(&bytes);
        assert_eq!(hex, "000fa5ff10");
        assert_eq!(decode(&hex).as_deref(), Some(&bytes[..]));
    }

    #[test]
    fn rejects_odd_len_and_uppercase_and_nonhex() {
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("AB"), None);
        assert_eq!(decode("zz"), None);
    }
}
