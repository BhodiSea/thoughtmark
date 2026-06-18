// SPDX-License-Identifier: Apache-2.0
//! The no-float rule (arch §4.3, I4).
//!
//! WASM has documented NaN-payload and signed-zero nondeterminism, so floats are forbidden anywhere on the
//! canonicalization / hashing path. [`validate_no_float`] rejects any non-integer JSON number, and any integer
//! outside the I-JSON safe range `[-(2^53 - 1), 2^53 - 1]`. It MUST run BEFORE canonicalization on all hashed
//! data. `serde_json`'s `arbitrary_precision` keeps oversized integers as their raw token so they survive the
//! parse and reach this walker (which then rejects them) instead of being coerced to `f64`.

use crate::canon::error::CanonError;
use alloc::string::ToString as _;
use alloc::vec::Vec;

/// `2^53 - 1` — the largest integer exactly representable in an IEEE-754 double / JS `Number`.
const I_JSON_MAX: i64 = 9_007_199_254_740_991;
/// `-(2^53 - 1)`.
const I_JSON_MIN: i64 = -9_007_199_254_740_991;

/// Reject any float, or any integer outside the I-JSON safe range, anywhere in `value`.
///
/// Uses an explicit stack (no recursion, no indexing) so deeply nested adversarial input cannot overflow the
/// native stack.
///
/// # Errors
/// [`CanonError::FloatNotAllowed`] for a non-integer number; [`CanonError::IntegerOutOfRange`] for an integer
/// outside `[-(2^53 - 1), 2^53 - 1]`.
pub fn validate_no_float(value: &serde_json::Value) -> Result<(), CanonError> {
    let mut stack: Vec<&serde_json::Value> = Vec::new();
    stack.push(value);
    while let Some(node) = stack.pop() {
        match node {
            serde_json::Value::Number(n) => classify_number(n)?,
            serde_json::Value::Array(items) => stack.extend(items.iter()),
            serde_json::Value::Object(map) => stack.extend(map.values()),
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            }
        }
    }
    Ok(())
}

/// Classify a single JSON number. Deliberately avoids `as_f64` (which, under `arbitrary_precision`, would lossily
/// accept a 60-digit integer and defeat the range check); classifies via the exact integer accessors plus a
/// raw-token scan for the big-integer / float fallback.
fn classify_number(n: &serde_json::Number) -> Result<(), CanonError> {
    if let Some(i) = n.as_i64() {
        return if (I_JSON_MIN..=I_JSON_MAX).contains(&i) {
            Ok(())
        } else {
            Err(CanonError::IntegerOutOfRange)
        };
    }
    if let Some(u) = n.as_u64() {
        // Any u64 above i64::MAX is necessarily above I_JSON_MAX.
        return if u <= I_JSON_MAX as u64 {
            Ok(())
        } else {
            Err(CanonError::IntegerOutOfRange)
        };
    }
    // Fits neither i64 nor u64: a float (has '.', 'e', or 'E') or a big integer.
    let token = n.to_string();
    if token.bytes().any(|b| b == b'.' || b == b'e' || b == b'E') {
        Err(CanonError::FloatNotAllowed)
    } else {
        Err(CanonError::IntegerOutOfRange)
    }
}
