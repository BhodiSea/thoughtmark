// SPDX-License-Identifier: Apache-2.0
//! Signing round-trips and the `verify_strict` boundary (arch §7). Integration tests opt out of the no-panic wall.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use thoughtmark_core::sign::Signer as _;
use thoughtmark_core::{
    DSSE_PAYLOAD_TYPE, Signature, TmSigner, decode_did_key, encode_did_key, pae, verify,
    verify_envelope,
};

fn signer() -> TmSigner {
    let probe = TmSigner::from_seed([42u8; 32], String::new());
    let did = encode_did_key(probe.verifying_key());
    TmSigner::from_seed([42u8; 32], did)
}

#[test]
fn pae_matches_dsse_spec_example() {
    // The canonical DSSE PAE example.
    assert_eq!(
        pae("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
}

#[test]
fn sign_then_verify_envelope_round_trips() {
    let s = signer();
    let payload = br#"{"hello":"world"}"#;
    let envelope = s.sign_payload(payload);
    assert_eq!(envelope.payload_type, DSSE_PAYLOAD_TYPE);
    assert_eq!(envelope.signatures.len(), 1); // ADR-0007: exactly one signature
    let recovered = verify_envelope(&envelope, &[*s.verifying_key()]).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn verify_rejects_tampered_signature() {
    let s = signer();
    let msg = b"sign me";
    let mut sig = s.sign(msg).0;
    sig[0] ^= 0xff;
    assert!(verify(s.verifying_key(), msg, &Signature(sig)).is_err());
}

#[test]
fn verify_envelope_rejects_wrong_key() {
    let s = signer();
    let other = TmSigner::from_seed([99u8; 32], String::new());
    let envelope = s.sign_payload(br#"{"x":1}"#);
    assert!(verify_envelope(&envelope, &[*other.verifying_key()]).is_err());
}

#[test]
fn did_key_round_trips() {
    let s = signer();
    let did = encode_did_key(s.verifying_key());
    assert!(did.starts_with("did:key:z6Mk")); // Ed25519 multicodec prefix
    let decoded = decode_did_key(&did).unwrap();
    assert_eq!(decoded.to_bytes(), s.verifying_key().to_bytes());
}

#[test]
fn did_key_fails_closed_on_garbage() {
    assert!(decode_did_key("did:key:zNotValidBase58!!!").is_err());
    assert!(decode_did_key("did:web:example.com").is_err());
    assert!(decode_did_key("z6Mk-no-prefix").is_err());
}
