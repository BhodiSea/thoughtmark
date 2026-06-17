// SPDX-License-Identifier: Apache-2.0
//! `thoughtmark-wasm` — the WASM/TypeScript binding seam.
//!
//! The only crate that may use `unsafe` (wasm-bindgen emits it) and the only place `getrandom`'s JS backend is
//! confined. The boundary carries only `Uint8Array` / `string` / `bigint` — never structured JS objects — so no
//! JS-side re-encoding can perturb byte-identity (I1). This module is a thin pass-through to
//! `thoughtmark_core::ops`; it adds no logic of its own.

use thoughtmark_core::ops;
use wasm_bindgen::prelude::wasm_bindgen;

/// Run a named thoughtmark operation over input bytes, returning the operation's canonical output bytes (or the
/// canonical error envelope). Byte-identical to the native Rust core for every `spec/vectors/` case (CORE-1).
#[wasm_bindgen]
#[must_use]
pub fn run_op(op: &str, input: &[u8]) -> Vec<u8> {
    ops::run_op(op, input)
}

/// The canonicalization format identifier, mirrored from the core (`"tm-jcs-1"`). Returned as a string so the
/// version tag stays exact across the boundary.
#[wasm_bindgen]
#[must_use]
pub fn canon_version() -> String {
    thoughtmark_core::CANON_VERSION.to_owned()
}
