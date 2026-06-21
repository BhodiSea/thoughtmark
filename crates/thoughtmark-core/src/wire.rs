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
    pub(crate) fn is_canonical(s: &str) -> bool {
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

/// `serde` adapter for an `Option<u64>` carried as a canonical decimal string (e.g. a `CheckDetail` tree size).
/// Mirrors [`dec_u64`] but tolerates an absent value (paired with `skip_serializing_if = "Option::is_none"`).
pub(crate) mod dec_u64_opt {
    use alloc::string::{String, ToString as _};
    use serde::{Deserialize as _, Deserializer, Serializer};

    // serde's `with` adapter dictates the `&Option<u64>` signature even though `Option<&u64>` would be idiomatic.
    #[allow(clippy::ref_option)]
    pub(crate) fn serialize<S: Serializer>(
        value: &Option<u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serializer.serialize_str(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                if !super::dec_u64::is_canonical(&s) {
                    return Err(serde::de::Error::custom(
                        "expected a canonical decimal u64 string",
                    ));
                }
                s.parse::<u64>()
                    .map(Some)
                    .map_err(|_| serde::de::Error::custom("u64 decimal string out of range"))
            }
        }
    }
}

/// `serde` adapter for a `Vec` of opaque byte blobs, each carried as a STANDARD-padded base64 string (the stapled
/// canonical `Turn`/`RunManifest` bodies in a [`crate::ThoughtmarkBundle`]) — never a JSON number array.
pub(crate) mod bytes_b64_vec {
    use alloc::string::String;
    use alloc::vec::Vec;
    use serde::ser::SerializeSeq as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        items: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(items.len()))?;
        for item in items {
            seq.serialize_element(&crate::base64::encode_std(item))?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        let strs = Vec::<String>::deserialize(deserializer)?;
        let mut out = Vec::with_capacity(strs.len());
        for s in &strs {
            out.push(
                crate::base64::decode_any(s)
                    .ok_or_else(|| serde::de::Error::custom("invalid base64"))?,
            );
        }
        Ok(out)
    }
}

/// `serde` adapter for opaque bytes carried as STANDARD-padded base64 (anchor proofs, checkpoint bytes) — never a
/// JSON number array.
pub(crate) mod bytes_b64 {
    use alloc::vec::Vec;
    use serde::{Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::base64::encode_std(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        crate::base64::decode_any(s).ok_or_else(|| serde::de::Error::custom("invalid base64"))
    }
}
