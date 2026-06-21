// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for the RFC 9162 consistency verifier (via the `merkle_verify_consistency` op): arbitrary input
//! bytes must never panic. The op parses an untrusted consistency proof and dual-recomputes both roots.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = thoughtmark_core::ops::run_op("merkle_verify_consistency", data);
});
