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
use crate::envelope::{error_envelope, success_envelope};
use crate::error::{Error, ErrorCode};
use crate::merkle::{self, ConsistencyProof, InclusionProof, TreeHash};
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
        _ => Err(Error::internal("ops.unknown_op")),
    }
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
