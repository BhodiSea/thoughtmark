// SPDX-License-Identifier: Apache-2.0
//! Dev-only conformance harness.
//!
//! Loads the language-neutral `spec/vectors/` corpus (the directory-per-case layout, arch §13.2) and drives
//! `thoughtmark-core`. The native test executor (`tests/conformance.rs`), the `tm bless` CLI, and the
//! WASM/TypeScript executor all consume the SAME corpus, resolved identically via `$THOUGHTMARK_VECTORS` (default
//! `<repo>/spec/vectors`), so the cross-language byte-identity gate (CORE-1) is real.
//!
//! Each manifest case maps 1:1 to a `run_op(op, input)` call: positive cases compare the output bytes to the
//! case's `expected` file; negative cases assert the `ErrorCode` embedded in the error envelope equals the case's
//! `expect_error` token (fail-closed).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// How a case's `run_op` output is checked.
pub enum Check {
    /// Positive: the output bytes MUST equal these exact bytes.
    Bytes(Vec<u8>),
    /// Negative: the output MUST be an error envelope carrying this SCREAMING_SNAKE_CASE code.
    Error(String),
}

/// A single conformance case, fully resolved (input + expectation loaded from disk).
pub struct Vector {
    /// Stable, human-readable id (e.g. `canon/0001`).
    pub id: String,
    /// The SPEC.md requirement id this case traces to.
    pub spec_req: String,
    /// The `run_op` dispatch token (e.g. `canonicalize`, `hash_blake3`, `cid_v1`).
    pub op: String,
    /// Raw input bytes (the case's `input.json` / `input.bin`).
    pub input: Vec<u8>,
    /// The expectation.
    pub check: Check,
}

/// Resolve the corpus directory: `$THOUGHTMARK_VECTORS` if set, else `<repo>/spec/vectors`.
#[must_use]
pub fn vectors_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("THOUGHTMARK_VECTORS") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn read_manifest(root: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    let text = fs::read_to_string(root.join("manifest.json"))?;
    Ok(serde_json::from_str(&text)?)
}

fn str_field(value: &serde_json::Value, key: &str) -> Result<String, Box<dyn Error>> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("manifest case missing string field `{key}`").into())
}

/// Load and resolve every case declared in `manifest.json` (the manifest is the source of truth for which file is
/// input vs expected; there is no blind directory walk).
///
/// # Errors
/// Returns an error if the manifest or any referenced file is missing or malformed.
pub fn load_all() -> Result<Vec<Vector>, Box<dyn Error>> {
    let root = vectors_dir();
    let manifest = read_manifest(&root)?;
    let cases = manifest
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("manifest.json: missing `cases` array")?;

    let mut out = Vec::with_capacity(cases.len());
    for case in cases {
        let id = str_field(case, "id")?;
        let spec_req = str_field(case, "spec_req")?;
        let op = str_field(case, "op")?;
        let input = fs::read(root.join(str_field(case, "input")?))?;
        let check = if let Some(code) = case.get("expect_error").and_then(serde_json::Value::as_str)
        {
            Check::Error(code.to_owned())
        } else {
            Check::Bytes(fs::read(root.join(str_field(case, "expected")?))?)
        };
        out.push(Vector {
            id,
            spec_req,
            op,
            input,
            check,
        });
    }
    Ok(out)
}

/// The expected total vector count declared in the manifest (asserted equal by both executors for cross-language
/// count parity, R13).
///
/// # Errors
/// Returns an error if the manifest is missing or lacks a `vector_count`.
pub fn expected_vector_count() -> Result<usize, Box<dyn Error>> {
    let manifest = read_manifest(&vectors_dir())?;
    let count = manifest
        .get("vector_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or("manifest.json: missing `vector_count`")?;
    Ok(usize::try_from(count)?)
}

/// Parse `{"ok":false,"error":{"code":"..."}}` → the code token.
#[must_use]
pub fn extract_error_code(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("ok")?.as_bool()? {
        return None;
    }
    value.get("error")?.get("code")?.as_str().map(str::to_owned)
}

/// Drive `thoughtmark-core` for a vector and check it. Returns `Ok(())` or a descriptive failure message.
///
/// # Errors
/// Returns a human-readable failure string on any mismatch.
pub fn run(vector: &Vector) -> Result<(), String> {
    let actual = thoughtmark_core::ops::run_op(&vector.op, &vector.input);
    match &vector.check {
        Check::Bytes(expected) => {
            if &actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "{} (op {}): output != expected ({} vs {} bytes)",
                    vector.id,
                    vector.op,
                    actual.len(),
                    expected.len()
                ))
            }
        }
        Check::Error(code) => match extract_error_code(&actual) {
            Some(got) if &got == code => Ok(()),
            Some(got) => Err(format!(
                "{}: error code {got} != expected {code}",
                vector.id
            )),
            None => Err(format!(
                "{}: expected an error envelope, got {} bytes",
                vector.id,
                actual.len()
            )),
        },
    }
}
