// SPDX-License-Identifier: Apache-2.0
//! Shared scalar wire forms (arch §5.1) — the determinism-critical types.
//!
//! [`SchemaVersion`] serializes as the OBJECT `{"major","minor","patch"}` (a tuple struct would emit the array
//! `[1,0,0]`). [`CanonVersion`] is the typed `canon_version`, serialized as its `as_str()` (`"tm-jcs-1"`) with a
//! fail-closed `parse`. [`CanonicalValue`] is the float-free `extensions`/`provider_params` value — there is no
//! `f64` variant, so JCS stays deterministic. `UnixMillis` (the decimal-string time) is re-exported from
//! `thoughtmark-core` (the audited wire scalar), not redefined here.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Schema version, serialized as the object `{"major":1,"minor":0,"patch":0}`.
///
/// A named-field struct (not a tuple struct), so the derived serde emits the object form; `deny_unknown_fields`
/// keeps it fail-closed. An example test pins the object shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersion {
    /// Major version (incompatible schema change).
    pub major: u16,
    /// Minor version (backward-compatible addition).
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

impl SchemaVersion {
    /// The current schema version, `1.0.0`.
    pub const V1: SchemaVersion = SchemaVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

/// The canonicalization format identifier, as a typed value.
///
/// Serializes as its [`CanonVersion::as_str`] (`"tm-jcs-1"`, identical to `thoughtmark_core::CANON_VERSION`).
/// [`CanonVersion::parse`] is fail-closed: an unknown token deserializes to a serde error carrying the
/// `UNKNOWN_CANON_VERSION` code (never best-effort recompute — arch §16). `#[non_exhaustive]` so a future
/// `canon_v2` is a MINOR.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonVersion {
    /// `"tm-jcs-1"` — the v1 RFC 8785 JCS canonicalization.
    TmJcs1,
}

impl CanonVersion {
    /// The stable wire token for this version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CanonVersion::TmJcs1 => "tm-jcs-1",
        }
    }

    /// Parse a wire token, fail-closed (`None` for an unknown version).
    #[must_use]
    pub fn parse(token: &str) -> Option<CanonVersion> {
        match token {
            "tm-jcs-1" => Some(CanonVersion::TmJcs1),
            _ => None,
        }
    }
}

impl serde::Serialize for CanonVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CanonVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = <&str as serde::Deserialize>::deserialize(deserializer)?;
        // Carry the stable ErrorCode token in the serde error so a malformed canon_version stays fail-closed.
        CanonVersion::parse(token).ok_or_else(|| serde::de::Error::custom("UNKNOWN_CANON_VERSION"))
    }
}

/// A float-free JSON value for the `extensions` / `provider_params` escape hatches (arch §5.1).
///
/// There is no `f64` variant, so canonicalization stays deterministic (I4). Integers outside the I-JSON safe
/// range are the caller's responsibility to carry as [`CanonicalValue::Str`] (a decimal string), exactly as
/// `UnixMillis` and `seed` do — `validate_no_float` rejects an out-of-range `Int` at canonicalize time. Maps use
/// `BTreeMap` for deterministic key order; `#[serde(untagged)]` so a value serializes AS the underlying JSON (no
/// tag wrapper).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CanonicalValue {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A JSON integer within the I-JSON safe range.
    Int(i64),
    /// A JSON string.
    Str(String),
    /// A JSON array.
    Arr(Vec<CanonicalValue>),
    /// A JSON object (deterministic key order).
    Obj(BTreeMap<String, CanonicalValue>),
}
