// SPDX-License-Identifier: Apache-2.0
//! C2SP signed-note checkpoint round-trips + the wire-format contract (LOG-4). A signed note MUST carry the
//! mandatory blank-line separator (a lone `\n`) between the signed text and the signature block, and the signed
//! text MUST end in a newline but EXCLUDE that blank line (c2sp.org/signed-note). Getting this wrong silently
//! produces notes no other signed-note implementation (sigsum / Go checksum DB / sunlight) can verify, and makes
//! this verifier reject every real checkpoint — so it is pinned here, not just in the cross-language corpus.
//! Integration tests opt out of the no-panic wall — a panic IS the failure signal.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use thoughtmark_core::{
    Checkpoint, TmSigner, TreeHash, VerifyingKey, checkpoint_body, encode_did_key, sign_checkpoint,
    verify_checkpoint,
};

fn signer() -> (TmSigner, VerifyingKey) {
    let probe = TmSigner::from_seed([7u8; 32], String::new());
    let vk = *probe.verifying_key();
    let did = encode_did_key(&vk);
    (TmSigner::from_seed([7u8; 32], did), vk)
}

fn demo_checkpoint() -> Checkpoint {
    Checkpoint {
        origin: "thoughtmark.dev/log/test".to_string(),
        size: 7,
        root: TreeHash::from_bytes([0x11; 32]),
        extensions: Vec::new(),
    }
}

#[test]
fn note_carries_blank_line_separator_and_signs_text_only() {
    let (s, vk) = signer();
    let keyname = "thoughtmark.dev/log/test";
    let body = checkpoint_body(&demo_checkpoint());
    let note = sign_checkpoint(&body, keyname, &vk, &s);

    // The note MUST contain the mandatory blank-line separator.
    let sep = note
        .windows(2)
        .position(|w| w == b"\n\n")
        .expect("a C2SP signed note has a blank-line separator before its signatures");

    // The SIGNED text is exactly `body` (ending in a single newline) — NOT body + blank line.
    assert_eq!(
        &note[..=sep],
        body.as_slice(),
        "the signed text must include its final newline but exclude the separating blank line"
    );

    // The signature line directly follows the blank line and starts with the em-dash prefix.
    assert_eq!(&note[sep..sep + 2], b"\n\n");
    assert_eq!(&note[sep + 2..sep + 6], "— ".as_bytes());
}

#[test]
fn sign_then_verify_round_trips() {
    let (s, vk) = signer();
    let keyname = "thoughtmark.dev/log/test";
    let cp = demo_checkpoint();
    let note = sign_checkpoint(&checkpoint_body(&cp), keyname, &vk, &s);
    let recovered = verify_checkpoint(&note, keyname, &vk).unwrap();
    assert_eq!(recovered, cp);
}

#[test]
fn round_trips_with_extensions() {
    let (s, vk) = signer();
    let keyname = "thoughtmark.dev/log/test";
    let cp = Checkpoint {
        origin: keyname.to_string(),
        size: 1_000_000,
        root: TreeHash::from_bytes([0x22; 32]),
        extensions: vec!["timestamp 1700000000".to_string(), "kind tiles".to_string()],
    };
    let note = sign_checkpoint(&checkpoint_body(&cp), keyname, &vk, &s);
    assert_eq!(verify_checkpoint(&note, keyname, &vk).unwrap(), cp);
}

#[test]
fn note_without_blank_line_is_rejected() {
    // The OLD, non-conformant shape (signature block glued directly after the text, no blank line) must fail
    // closed — exactly the regression this guards against.
    let (s, vk) = signer();
    let keyname = "thoughtmark.dev/log/test";
    let body = checkpoint_body(&demo_checkpoint());
    let note = sign_checkpoint(&body, keyname, &vk, &s);
    let sep = note.windows(2).position(|w| w == b"\n\n").unwrap();

    let mut no_blank = body.clone();
    no_blank.extend_from_slice(&note[sep + 2..]); // text + signature line, NO blank line
    assert!(
        verify_checkpoint(&no_blank, keyname, &vk).is_err(),
        "a note missing the blank-line separator must be rejected"
    );
}

#[test]
fn wrong_keyname_fails_the_matched_signature_requirement() {
    let (s, vk) = signer();
    let note = sign_checkpoint(
        &checkpoint_body(&demo_checkpoint()),
        "thoughtmark.dev/log/test",
        &vk,
        &s,
    );
    assert!(verify_checkpoint(&note, "some.other.log", &vk).is_err());
}
