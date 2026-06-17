// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for JCS canonicalization. Activates with Tier-0 logic in Phase 1 (the `jcs` parser); Phase 0
//! exercises the dispatch surface so the target compiles and the harness is wired.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = thoughtmark_core::ops::run_op("canonicalize", data);
});
