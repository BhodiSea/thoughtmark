// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for DSSE envelope parsing + Ed25519 verification (via the `dsse_verify_envelope` / `ed25519_verify`
//! / `dsse_pae` ops): arbitrary input bytes must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = thoughtmark_core::ops::run_op("dsse_verify_envelope", data);
    let _ = thoughtmark_core::ops::run_op("ed25519_verify", data);
    let _ = thoughtmark_core::ops::run_op("dsse_pae", data);
});
