// SPDX-License-Identifier: Apache-2.0
//! Shared wire-encoding helpers.
//!
//! Tree sizes and leaf indices are `u64` and can exceed `2^53`, so — exactly like [`crate::UnixMillis`] — they
//! travel as a **canonical decimal STRING**, never a JSON number (I4 / I-JSON; the TS side reads them as
//! `bigint`). [`dec_u64`] is the `#[serde(with = ...)]` adapter; it accepts only the canonical form so a value
//! re-serializes byte-identically.

/// `serde` adapter for a `u64` carried as a canonical decimal string.
pub(crate) mod dec_u64 {
    use alloc::string::ToString as _;
    use serde::{Deserializer, Serializer};

    // serde's `with` adapter requires the `&u64` signature even though a `u64` is `Copy`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        if !is_canonical(s) {
            return Err(serde::de::Error::custom(
                "expected a canonical decimal u64 string",
            ));
        }
        s.parse::<u64>()
            .map_err(|_| serde::de::Error::custom("u64 decimal string out of range"))
    }

    /// True iff `s` is the canonical decimal form of a `u64`: a single `0`, or a non-zero digit followed by digits
    /// (no sign, no leading zeros). Iterates `chars` to stay inside the no-panic wall.
    fn is_canonical(s: &str) -> bool {
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !first.is_ascii_digit() {
            return false;
        }
        if first == '0' {
            return chars.next().is_none();
        }
        chars.all(|c| c.is_ascii_digit())
    }
}
