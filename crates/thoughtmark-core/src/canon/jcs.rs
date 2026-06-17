// SPDX-License-Identifier: Apache-2.0
//! The JCS canonicalization choke point (arch §4.2, ADR-0001 as amended).
//!
//! RFC 8785 JSON Canonicalization. This is the ONLY canonicalizer in the workspace. It is implemented in-house
//! over `serde_json::Value` because the audited `serde_json_canonicalizer` crate is `std`-only and cannot compile
//! in the `no_std` + `alloc` WASM core; that crate (and the independent pure-TS `cyberphone/canonicalize`) instead
//! serve as differential test oracles — exactly the pattern ADR-0005 already uses for RFC 6962. Because
//! [`crate::canon::nofloat::validate_no_float`] runs first and rejects every float and out-of-range integer, the
//! only number form this encoder ever emits is a plain in-range integer decimal — so the hard part of RFC 8785
//! (ECMAScript float formatting) is never exercised, and byte-identity with the oracles is tractable.
//!
//! The four pinned RFC 8785 behaviors: **UTF-16 code-unit key sort** (NOT Rust `str` / code-point order — the
//! astral-plane divergence that killed `serde_jcs`); minimal string escaping (§3.2.2.2); integer-only numbers; no
//! insignificant whitespace.

use crate::canon::error::CanonError;
use crate::canon::nofloat::validate_no_float;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::fmt;
use serde::Serialize;
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Canonicalize any `Serialize` value to RFC 8785 JCS bytes.
///
/// # Errors
/// Returns a [`CanonError`] if the value cannot be represented as I-JSON (e.g. it contains a float).
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonError> {
    let value = serde_json::to_value(value).map_err(|_| CanonError::InvalidJson)?;
    canonicalize_value(&value)
}

/// Canonicalize an already-parsed [`serde_json::Value`]. A `Value` cannot carry duplicate keys, so only the
/// no-float rule is enforced here.
///
/// # Errors
/// Returns a [`CanonError`] if the value contains a float or out-of-range integer.
pub fn canonicalize_value(value: &Value) -> Result<Vec<u8>, CanonError> {
    validate_no_float(value)?;
    let mut out = Vec::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// Canonicalize a UTF-8 JSON document — the WASM/TS-boundary entry point.
///
/// Parses with `arbitrary_precision` (so oversized integers survive to be rejected), enforces the no-float rule,
/// then rejects duplicate object keys (I-JSON), then encodes.
///
/// # Errors
/// [`CanonError::InvalidJson`] (malformed / non-UTF-8 / duplicate key collapses here via the code mapping),
/// [`CanonError::FloatNotAllowed`], or [`CanonError::IntegerOutOfRange`].
pub fn canonicalize_str(json: &str) -> Result<Vec<u8>, CanonError> {
    let value: Value = serde_json::from_str(json).map_err(|_| CanonError::InvalidJson)?;
    // no-float runs BEFORE the duplicate-key check, so the dup-key walker only ever sees float-free input (it does
    // not handle `f64`, which the `disallowed-types` lint forbids us from naming).
    validate_no_float(&value)?;
    reject_duplicate_keys(json)?;
    let mut out = Vec::new();
    write_value(&mut out, &value)?;
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------------------
// In-house RFC 8785 encoder
// ---------------------------------------------------------------------------------------------------------------

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), CanonError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(out, n)?,
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                write_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785: sort members by the UTF-16 code units of their keys. We never rely on the map's own order.
            let mut entries: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect::<Vec<u16>>(), k, v))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (_, key, val)) in entries.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                write_value(out, val)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Emit an integer in plain decimal. After `validate_no_float`, every number is an integer in the I-JSON range and
/// therefore fits `i64`; re-deriving the decimal from the integer value (not the raw token) guarantees ECMAScript
/// integer `toString` semantics (e.g. `-0` → `0`). The final arm is unreachable post-validation; it fails closed.
fn write_number(out: &mut Vec<u8>, n: &serde_json::Number) -> Result<(), CanonError> {
    if let Some(i) = n.as_i64() {
        out.extend_from_slice(i.to_string().as_bytes());
        Ok(())
    } else if let Some(u) = n.as_u64() {
        out.extend_from_slice(u.to_string().as_bytes());
        Ok(())
    } else {
        Err(CanonError::FloatNotAllowed)
    }
}

/// Emit a JSON string with RFC 8785 §3.2.2.2 escaping: only `"`, `\`, and C0 controls are escaped (short escapes
/// where defined, else lowercase `\u00XX`); every other code point is emitted as raw UTF-8.
fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.extend_from_slice(crate::hex::encode_lower(&[c as u8]).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ---------------------------------------------------------------------------------------------------------------
// Duplicate-key rejection (I-JSON). serde_json's `Value` silently keeps the last of duplicate keys, so it cannot
// be used to detect them; this walks the raw input with a serde `Visitor` that errors when a key repeats. It runs
// only after `validate_no_float`, so no float ever reaches `visit_f64` (left as the trait default).
// ---------------------------------------------------------------------------------------------------------------

fn reject_duplicate_keys(json: &str) -> Result<(), CanonError> {
    let mut de = serde_json::Deserializer::from_str(json);
    DupKeyCheck::deserialize(&mut de).map_err(|_| CanonError::DuplicateKey)?;
    de.end().map_err(|_| CanonError::InvalidJson)?;
    Ok(())
}

struct DupKeyCheck;

impl<'de> Deserialize<'de> for DupKeyCheck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DupKeyVisitor)
    }
}

struct DupKeyVisitor;

impl<'de> Visitor<'de> for DupKeyVisitor {
    type Value = DupKeyCheck;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_i128<E>(self, _v: i128) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_u128<E>(self, _v: u128) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DupKeyCheck)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        DupKeyCheck::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<DupKeyCheck>()?.is_some() {}
        Ok(DupKeyCheck)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(A::Error::custom("duplicate object key"));
            }
            map.next_value::<DupKeyCheck>()?;
        }
        Ok(DupKeyCheck)
    }
}
