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

    for vector in &vectors {
        let actual = tk::run(vector);
        assert_eq!(
            actual, vector.expected_bytes,
            "vector {} (spec_req {}, op {}): native Rust output != expected bytes",
            vector.vector_id, vector.spec_req, vector.op
        );
    }

    // Emit the count so the Node executor can assert it saw the SAME number of vectors (R13).
    println!("THOUGHTMARK_CONFORMANCE_COUNT={}", vectors.len());
    eprintln!(
        "conformance: {} vectors byte-identical (native Rust)",
        vectors.len()
    );
}
