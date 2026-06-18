// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for the RFC 9162 inclusion verifier (via the `merkle_verify_inclusion` op): arbitrary input bytes
//! must never panic — a panic crossing the WASM boundary is an uncatchable `RuntimeError` (a hole in the no-panic
//! wall). The op parses untrusted proof JSON and runs the iterative verifier.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = thoughtmark_core::ops::run_op("merkle_verify_inclusion", data);
    let _ = thoughtmark_core::ops::run_op("merkle_root", data);
});
