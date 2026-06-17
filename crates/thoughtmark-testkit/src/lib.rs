// SPDX-License-Identifier: Apache-2.0
//! Dev-only conformance harness.
//!
//! Loads the language-neutral `spec/vectors/` corpus and drives `thoughtmark-core`. The native test executor
//! (`tests/conformance.rs`) and the WASM/TypeScript executor both consume the SAME corpus, resolved identically
//! via `$THOUGHTMARK_VECTORS` (default `<repo>/spec/vectors`), so the cross-language byte-identity gate
//! (CORE-1/CORE-2) is real and not silently weakened by divergent inputs.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// A single conformance case parsed from `spec/vectors/<op>/<id>.json`.
pub struct Vector {
    /// Stable, human-readable case id (e.g. `canon-0001`).
    pub vector_id: String,
    /// The SPEC.md requirement id this case traces to (e.g. `CANON-1`).
    pub spec_req: String,
    /// The operation dispatched through [`thoughtmark_core::ops::run_op`].
    pub op: String,
    /// Expected output bytes, decoded from the vector's `expected_bytes_b64`.
    pub expected_bytes: Vec<u8>,
}

/// Resolve the corpus directory: `$THOUGHTMARK_VECTORS` if set, else `<repo>/spec/vectors`.
#[must_use]
pub fn vectors_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("THOUGHTMARK_VECTORS") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "json")
            && path.file_name().is_some_and(|name| name != "manifest.json")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn field(json: &serde_json::Value, key: &str) -> Result<String, Box<dyn Error>> {
    json.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("vector missing string field `{key}`").into())
}

/// Load and parse every vector in the corpus, sorted by path for deterministic ordering.
///
/// # Errors
/// Returns an error if the corpus directory cannot be read, or a vector file is malformed or has an undecodable
/// `expected_bytes_b64`.
pub fn load_all() -> Result<Vec<Vector>, Box<dyn Error>> {
    use base64::Engine as _;

    let dir = vectors_dir();
    let mut files = Vec::new();
    collect_json(&dir, &mut files)?;
    files.sort();

    let mut vectors = Vec::with_capacity(files.len());
    for path in files {
        let text = fs::read_to_string(&path)?;
        let json: serde_json::Value = serde_json::from_str(&text)?;
        let expected_bytes = base64::engine::general_purpose::STANDARD
            .decode(field(&json, "expected_bytes_b64")?.as_bytes())?;
        vectors.push(Vector {
            vector_id: field(&json, "vector_id")?,
            spec_req: field(&json, "spec_req")?,
            op: field(&json, "op")?,
            expected_bytes,
        });
    }
    Ok(vectors)
}

/// Drive `thoughtmark-core` for a vector and return the actual output bytes.
///
/// Phase 0 operations ignore their input (CORE-2: `NOT_IMPLEMENTED` regardless); canonical input wiring lands
/// alongside Tier-0 logic in Phase 1.
#[must_use]
pub fn run(vector: &Vector) -> Vec<u8> {
    thoughtmark_core::ops::run_op(&vector.op, &[])
}
