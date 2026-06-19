// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for the offline `did:key` decoder (via the `did_key_decode` op): arbitrary input bytes (including
//! invalid UTF-8, bad base58, wrong multicodec, off-curve keys) must never panic — always fail closed.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = thoughtmark_core::ops::run_op("did_key_decode", data);
});
