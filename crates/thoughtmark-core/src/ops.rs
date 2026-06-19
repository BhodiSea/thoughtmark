// SPDX-License-Identifier: Apache-2.0
//! The string-dispatched operation entry point (the single cross-language seam).
//!
//! [`run_op`] is shared byte-for-byte by the native conformance runner and the WASM binding. Each op is a pure
//! `bytes -> bytes` function: on success it returns the operation's canonical output bytes; on error it returns
//! the canonical error envelope ([`crate::envelope::error_envelope`]) carrying the stable [`ErrorCode`] token.
//! Keeping every op expressible as `bytes -> bytes` is what lets the WASM/TS boundary carry only `Uint8Array`.
//!
//! Output encodings: `canonicalize` → raw JCS bytes; `hash_blake3`/`hash_sha256` → 64 lowercase hex bytes of
//! `hash(canonicalize(input))` (canonicalize-then-hash, exercising I2); `cid_v1` → the base32-lower CID string of
//! the RAW blob; `hash_domain_*` → 64 hex bytes of the domain-separated hash (binding `CANON_VERSION` into the
//! preimage).

use crate::canon::{self, HashAlg};
use crate::dsse::{self, DsseEnvelope};
use crate::envelope::{error_envelope, success_envelope};
use crate::error::{Error, ErrorCode};
use crate::merkle::{self, ConsistencyProof, InclusionProof, TreeHash};
use crate::sign::{self, Signature, TmSigner, VerifyingKey};
use alloc::string::String;
use alloc::vec::Vec;

/// Dispatch a named operation over raw input bytes and return its canonical output bytes (or the error envelope).
#[must_use]
pub fn run_op(op: &str, input: &[u8]) -> Vec<u8> {
    match dispatch(op, input) {
        Ok(bytes) => bytes,
        Err(err) => error_envelope(err.code()),
    }
}

fn dispatch(op: &str, input: &[u8]) -> Result<Vec<u8>, Error> {
    match op {
        "canonicalize" => Ok(canon::canonicalize_str(as_str(input)?)?),
        "hash_blake3" => hash_json(HashAlg::Blake3, input),
        "hash_sha256" => hash_json(HashAlg::Sha256, input),
        "cid_v1" => {
            let cid = canon::cid_blob(HashAlg::Blake3, input)?;
            Ok(canon::cid_to_string(&cid)?.into_bytes())
        }
        "hash_domain_turn" => hash_domain_json(canon::domain::TURN, input),
        "hash_domain_object" => hash_domain_json(canon::domain::OBJECT, input),
        "hash_domain_manifest" => hash_domain_json(canon::domain::MANIFEST, input),
        "trail_root" => trail_root_json(input),
        "merkle_root" => op_merkle_root(input),
        "merkle_verify_inclusion" => op_merkle_verify_inclusion(input),
        "merkle_verify_consistency" => op_merkle_verify_consistency(input),
        "dsse_pae" => op_dsse_pae(input),
        "ed25519_verify" => op_ed25519_verify(input),
        "did_key_decode" => op_did_key_decode(input),
        "dsse_verify_envelope" => op_dsse_verify_envelope(input),
        "sign_statement" => op_sign_statement(input),
        _ => Err(Error::internal("ops.unknown_op")),
    }
}

/// Decode a hex string into a fixed-size byte array, mapping any failure to `code`.
fn hex_array<const N: usize>(hex: &str, code: ErrorCode) -> Result<[u8; N], Error> {
    let bytes = crate::hex::decode(hex).ok_or(Error::Signature(code))?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| Error::Signature(code))
}

/// A UTF-8 view of the input, or a content-free invalid-JSON error.
fn as_str(input: &[u8]) -> Result<&str, Error> {
    core::str::from_utf8(input).map_err(|_| Error::Canon(ErrorCode::CanonInvalidJson))
}

/// Canonicalize a JSON input then hash it with `alg`, returning lowercase hex (exercises I2: JCS-before-hash).
fn hash_json(alg: HashAlg, input: &[u8]) -> Result<Vec<u8>, Error> {
    let canonical = canon::canonicalize_str(as_str(input)?)?;
    Ok(canon::hash_with(alg, &canonical).to_hex().into_bytes())
}

/// Canonicalize a JSON input then domain-separate-hash it (BLAKE3), returning lowercase hex.
fn hash_domain_json(domain: &str, input: &[u8]) -> Result<Vec<u8>, Error> {
    let canonical = canon::canonicalize_str(as_str(input)?)?;
    Ok(canon::hash_domain(HashAlg::Blake3, domain, &canonical)
        .to_hex()
        .into_bytes())
}

/// The `trail_root` derivation (SCHEMA-3): canonicalize the trail JSON, then emit the dual digest map
/// `{"blake3":hex,"sha256":hex}` (both over the SAME canonical bytes, in the `OBJECT` domain). The output is
/// already JCS-canonical (`"blake3"` < `"sha256"`), byte-identical to canonicalizing the schema's
/// `trail_root` `BTreeMap`. This is the one schema-derivation op that needs both hash algorithms, so it cannot
/// reuse `hash_domain_*`; it stays raw-JSON so `core::ops` never depends on `thoughtmark-schema`.
fn trail_root_json(input: &[u8]) -> Result<Vec<u8>, Error> {
    let canonical = canon::canonicalize_str(as_str(input)?)?;
    let blake3 = canon::hash_domain(HashAlg::Blake3, canon::domain::OBJECT, &canonical).to_hex();
    let sha256 = canon::hash_domain(HashAlg::Sha256, canon::domain::OBJECT, &canonical).to_hex();
    let mut out = Vec::new();
    out.extend_from_slice(b"{\"blake3\":\"");
    out.extend_from_slice(blake3.as_bytes());
    out.extend_from_slice(b"\",\"sha256\":\"");
    out.extend_from_slice(sha256.as_bytes());
    out.extend_from_slice(b"\"}");
    Ok(out)
}

/// `{"leaves":["<base64 record>", ...]}` → the base64 RFC 6962 Merkle tree hash (each record is leaf-hashed first;
/// an empty list hashes to `empty_root`). The root is base64, not hex — a `TreeHash` is deliberately distinct from
/// a content `Digest` (ADR-0013).
fn op_merkle_root(input: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Req {
        leaves: Vec<String>,
    }
    let req: Req = serde_json::from_slice(input)
        .map_err(|_| Error::Inclusion(ErrorCode::MerkleProofInvalid))?;
    let mut hashes = Vec::with_capacity(req.leaves.len());
    for record_b64 in &req.leaves {
        let record = crate::base64::decode_any(record_b64)
            .ok_or(Error::Inclusion(ErrorCode::MerkleProofInvalid))?;
        hashes.push(merkle::hash_leaf(&record));
    }
    let root = merkle::merkle_tree_hash(&hashes);
    Ok(crate::base64::encode_std(root.as_bytes()).into_bytes())
}

/// `{"leaf":"<base64 record>","proof":<InclusionProof>,"root":"<TreeHash>"}` → success/error envelope (RFC 9162
/// §2.1.3.2). The leaf record is leaf-hashed before verification.
fn op_merkle_verify_inclusion(input: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Req {
        leaf: String,
        proof: InclusionProof,
        root: TreeHash,
    }
    let req: Req = serde_json::from_slice(input)
        .map_err(|_| Error::Inclusion(ErrorCode::MerkleProofInvalid))?;
    let record = crate::base64::decode_any(&req.leaf)
        .ok_or(Error::Inclusion(ErrorCode::MerkleProofInvalid))?;
    let leaf_hash = merkle::hash_leaf(&record);
    merkle::verify_inclusion(&req.proof, &leaf_hash, &req.root)?;
    Ok(success_envelope())
}

/// `{"proof":<ConsistencyProof>,"old_root":"<TreeHash>","new_root":"<TreeHash>"}` → success/error envelope
/// (RFC 9162 §2.1.4.2).
fn op_merkle_verify_consistency(input: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Req {
        proof: ConsistencyProof,
        old_root: TreeHash,
        new_root: TreeHash,
    }
    let req: Req = serde_json::from_slice(input)
        .map_err(|_| Error::Consistency(ErrorCode::ConsistencyProofInvalid))?;
    merkle::verify_consistency(&req.proof, &req.old_root, &req.new_root)?;
    Ok(success_envelope())
}

/// `{"payload_type":"...","body_b64":"..."}` → the raw DSSE PAE bytes (`"DSSEv1" SP …`).
fn op_dsse_pae(input: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Req {
        payload_type: String,
        body_b64: String,
    }
    let req: Req =
        serde_json::from_slice(input).map_err(|_| Error::Dsse(ErrorCode::DsseBadEnvelope))?;
    let body =
        crate::base64::decode_any(&req.body_b64).ok_or(Error::Dsse(ErrorCode::DsseBadEnvelope))?;
    Ok(dsse::pae(&req.payload_type, &body))
}

/// `{"pubkey_hex":"...","msg_hex":"...","sig_hex":"..."}` → success/error envelope via `verify_strict`. Pins the
/// Ed25519 malleability/cofactor accept-reject boundary (the authoritative Wycheproof / speccheck cases).
fn op_ed25519_verify(input: &[u8]) -> Result<Vec<u8>, Error> {
    // The `*_hex` field names are the frozen wire keys (Wycheproof-style); the common postfix is intentional.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(clippy::struct_field_names)]
    struct Req {
        pubkey_hex: String,
        msg_hex: String,
        sig_hex: String,
    }
    let req: Req =
        serde_json::from_slice(input).map_err(|_| Error::Signature(ErrorCode::SigInvalid))?;
    let pubkey: [u8; 32] = hex_array(&req.pubkey_hex, ErrorCode::SigMalformedKey)?;
    let vk = VerifyingKey::from_bytes(&pubkey)?;
    let msg = crate::hex::decode(&req.msg_hex).ok_or(Error::Signature(ErrorCode::SigInvalid))?;
    let sig: [u8; 64] = hex_array(&req.sig_hex, ErrorCode::SigInvalid)?;
    sign::verify(&vk, &msg, &Signature(sig))?;
    Ok(success_envelope())
}

/// A raw `did:key:z…` UTF-8 string → the 32-byte public key as 64 lowercase hex, or `SIG_MALFORMED_KEY`.
fn op_did_key_decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let did =
        core::str::from_utf8(input).map_err(|_| Error::Signature(ErrorCode::SigMalformedKey))?;
    let vk = crate::did_key::decode_did_key(did)?;
    Ok(crate::hex::encode_lower(&vk.to_bytes()).into_bytes())
}

/// Resolve a verification key from either a `did:key:z…` string or a 64-char hex public key.
fn resolve_key(key: &str) -> Result<VerifyingKey, Error> {
    if key.starts_with("did:key:") {
        crate::did_key::decode_did_key(key)
    } else {
        let bytes: [u8; 32] = hex_array(key, ErrorCode::SigMalformedKey)?;
        VerifyingKey::from_bytes(&bytes)
    }
}

/// `{"envelope":<DsseEnvelope>,"keys":["<did:key or hex>", ...]}` → the raw (decoded) canonical payload bytes on
/// success, else an error envelope.
fn op_dsse_verify_envelope(input: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Req {
        envelope: DsseEnvelope,
        keys: Vec<String>,
    }
    let req: Req =
        serde_json::from_slice(input).map_err(|_| Error::Dsse(ErrorCode::DsseBadEnvelope))?;
    let mut keys = Vec::with_capacity(req.keys.len());
    for key in &req.keys {
        keys.push(resolve_key(key)?);
    }
    sign::verify_envelope(&req.envelope, &keys)
}

/// `{"seed_hex":"...","keyid":"...","statement":<json>}` → the canonical DSSE envelope JSON. Deterministic
/// (Ed25519 signing is deterministic given the seed), so it is a stable conformance vector.
fn op_sign_statement(input: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Req {
        seed_hex: String,
        keyid: String,
        statement: serde_json::Value,
    }
    let req: Req =
        serde_json::from_slice(input).map_err(|_| Error::Dsse(ErrorCode::DsseBadEnvelope))?;
    let seed: [u8; 32] = hex_array(&req.seed_hex, ErrorCode::SigMalformedKey)?;
    let signer = TmSigner::from_seed(seed, req.keyid);
    let payload = canon::canonicalize_value(&req.statement)?;
    let envelope = signer.sign_payload(&payload);
    Ok(canon::canonicalize(&envelope)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_round_trips_keys() {
        let out = run_op("canonicalize", br#"{"b":1,"a":2}"#);
        assert_eq!(out, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn hash_outputs_64_hex_chars() {
        let out = run_op("hash_blake3", br#"{"a":1}"#);
        assert_eq!(out.len(), 64);
        assert!(out.iter().all(u8::is_ascii_hexdigit));
    }

    #[test]
    fn cid_outputs_base32_lower() {
        let out = run_op("cid_v1", b"abc");
        assert_eq!(out.first(), Some(&b'b'));
    }

    #[test]
    fn errors_become_envelopes() {
        let out = run_op("canonicalize", br#"{"x":1.5}"#);
        assert_eq!(
            out,
            br#"{"ok":false,"error":{"code":"CANON_NON_DETERMINISTIC_FLOAT"}}"#
        );
        let dup = run_op("canonicalize", br#"{"a":1,"a":2}"#);
        assert_eq!(
            dup,
            br#"{"ok":false,"error":{"code":"CANON_INVALID_JSON"}}"#
        );
    }

    #[test]
    fn unknown_op_is_internal() {
        let out = run_op("frobnicate", b"");
        assert_eq!(out, br#"{"ok":false,"error":{"code":"INTERNAL"}}"#);
    }

    #[test]
    fn merkle_root_of_empty_is_base64_sha256_empty() {
        // base64(SHA-256("")) — the RFC 6962 empty-tree root.
        let out = run_op("merkle_root", br#"{"leaves":[]}"#);
        assert_eq!(out, b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn merkle_verify_inclusion_malformed_is_proof_invalid() {
        let out = run_op("merkle_verify_inclusion", br#"{"not":"a proof"}"#);
        assert_eq!(
            out,
            br#"{"ok":false,"error":{"code":"MERKLE_PROOF_INVALID"}}"#
        );
    }

    #[test]
    fn trail_root_is_canonical_dual_digest_map() {
        // {"blake3":"<64hex>","sha256":"<64hex>"} = 11 + 64 + 12 + 64 + 2 = 153 bytes, keys already JCS-sorted.
        let out = run_op("trail_root", br#"{"b":1,"a":2}"#);
        assert_eq!(out.len(), 153);
        assert!(out.starts_with(br#"{"blake3":""#));
        assert!(out.ends_with(br#""}"#));
        // The blake3 half must equal the standalone hash_domain_object op (same OBJECT-domain preimage).
        let b3 = run_op("hash_domain_object", br#"{"b":1,"a":2}"#);
        let mut prefix = Vec::from(&b"{\"blake3\":\""[..]);
        prefix.extend_from_slice(&b3);
        assert!(out.starts_with(&prefix));
    }
}
