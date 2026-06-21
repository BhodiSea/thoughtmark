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

// `CanonVersion` (the typed `canon_version` with its fail-closed serde) is defined in `thoughtmark_core::scalar`
// (the §14.3 core-types surface, reused by the §11 `verify` pipeline) and re-exported here so
// `thoughtmark_schema::CanonVersion` keeps resolving.
pub use thoughtmark_core::CanonVersion;

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
