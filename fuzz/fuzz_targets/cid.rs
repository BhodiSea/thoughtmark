// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for CIDv1 encoding/decoding. Activates with Tier-0 logic in Phase 1.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = thoughtmark_core::ops::run_op("cid_v1", data);
});
