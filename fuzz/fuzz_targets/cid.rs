// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzz target for CIDv1 encode + decode (Phase 1). Exercises BOTH the encoder (`run_op("cid_v1", …)`) and the
//! PARSER (`canon::cid_from_str`, which carries the BLAKE3 length-32 pinning rule — the malleability guard).
//! A panic on arbitrary input would breach the no-panic wall; a CID that does not round-trip would be a CID
//! malleability bug.
use libfuzzer_sys::fuzz_target;
use thoughtmark_core::canon;

fuzz_target!(|data: &[u8]| {
    // Encoder path: arbitrary blob -> CIDv1 base32-lower string.
    let _ = thoughtmark_core::ops::run_op("cid_v1", data);

    // Parser path: arbitrary (lossy-UTF-8) text must never panic and must fail closed on malformed input.
    let text = String::from_utf8_lossy(data);
    let _ = canon::cid_from_str(&text);

    // Round-trip invariant: a CID we just minted must parse back and re-encode to the identical string.
    if let Ok(cid) = canon::cid_blob(canon::HashAlg::Blake3, data) {
        if let Ok(s) = canon::cid_to_string(&cid) {
            match canon::cid_from_str(&s).and_then(|c| canon::cid_to_string(&c)) {
                Ok(roundtrip) => assert_eq!(roundtrip, s, "CID round-trip diverged"),
                Err(_) => panic!("a freshly-minted CID failed to parse back"),
            }
        }
    }
});
