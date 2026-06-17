// SPDX-License-Identifier: Apache-2.0
//! `thoughtmark-wasm` — the WASM/TypeScript binding seam.
//!
//! The only crate that may use `unsafe` (wasm-bindgen emits it) and the only place `getrandom`'s JS backend is
//! confined. The boundary carries only `Uint8Array` / `string` / `bigint` — never structured JS objects — so no
//! JS-side re-encoding can perturb byte-identity (I1). This module is a thin pass-through to
//! `thoughtmark_core::ops`; it adds no logic of its own.

use thoughtmark_core::ops;
use wasm_bindgen::prelude::wasm_bindgen;

/// Run a named thoughtmark operation over input bytes, returning canonical output bytes.
///
/// In Phase 0 this returns the canonical `NOT_IMPLEMENTED` envelope, byte-identical to the native Rust core, so
/// the cross-language conformance gate runs against stubs (CORE-1/CORE-2).
#[wasm_bindgen]
#[must_use]
pub fn run_op(op: &str, input: &[u8]) -> Vec<u8> {
    ops::run_op(op, input)
}

/// The canonicalization format version, mirrored from the core (placeholder `0` until Phase 1). The conformance
/// gate asserts this matches the native core's value.
#[wasm_bindgen]
#[must_use]
pub fn canon_version() -> u32 {
    0
}
