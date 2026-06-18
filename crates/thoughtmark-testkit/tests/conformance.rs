// SPDX-License-Identifier: Apache-2.0
//! Cross-language conformance — the NATIVE Rust executor (the single most load-bearing control, row 10).
//!
//! Asserts that `thoughtmark-core`'s output is byte-identical to every `spec/vectors/` case's expected bytes
//! (CORE-1/CORE-2). The WASM/TypeScript executor (`packages/core/test/conformance.test.ts`) asserts the same
//! against the same corpus; transitively, Rust ⟷ WASM/TS agree byte-for-byte. Against Phase-0 stubs every case
//! is the canonical `NOT_IMPLEMENTED` envelope — a genuine byte-equality assertion that stubs happen to satisfy.

// Test harness: a panic IS the failure signal, so relaxing the no-panic wall here is justified.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use thoughtmark_testkit as tk;

#[test]
fn rust_core_is_byte_identical_to_corpus() {
    let vectors = tk::load_all().expect("load the spec/vectors corpus");
    assert!(
        !vectors.is_empty(),
        "corpus is empty — the conformance gate would be vacuous (it must have teeth from the first PR)"
    );

    // Cross-language count parity (R13): every executor expands the manifest to the same number of cases.
    let expected_count = tk::expected_vector_count().expect("manifest vector_count");
    assert_eq!(
        vectors.len(),
        expected_count,
        "loaded {} cases but manifest declares vector_count={expected_count}",
        vectors.len()
    );

    let mut failures = Vec::new();
    for vector in &vectors {
        if let Err(msg) = tk::run(vector) {
            failures.push(format!(
                "vector {} (spec_req {}): {msg}",
                vector.id, vector.spec_req
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "native Rust conformance failures:\n{}",
        failures.join("\n")
    );

    // Emit the count so the Node executor can assert it saw the SAME number of vectors (R13).
    println!("THOUGHTMARK_CONFORMANCE_COUNT={}", vectors.len());
    eprintln!(
        "conformance: {} vectors byte-identical (native Rust)",
        vectors.len()
    );
}
