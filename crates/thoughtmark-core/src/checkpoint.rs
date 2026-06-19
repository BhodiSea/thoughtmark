// SPDX-License-Identifier: Apache-2.0
//! C2SP signed-note Signed-Tree-Head checkpoints (arch §6.4).
//!
//! Three exactness traps the vectors pin: (1) the signature line prefix is **em-dash + space** (U+2014 `0xE2 0x80
//! 0x94`, then `0x20`), NOT a hyphen; (2) [`verify_checkpoint`] MUST assert **≥1 signature line actually matched**
//! a known key — the note spec mandates ignoring unknown signatures, so a "verified" note could otherwise carry
//! zero valid ones; (3) a **mandatory blank-line separator** (a lone `\n`) sits between the signed text and the
//! signature block (c2sp.org/signed-note) — the signed text ends in a newline but does NOT include the blank
//! line, and getting this wrong makes the note un-interoperable with every other signed-note implementation
//! (sigsum, the Go checksum DB, sunlight). The key-hash is `SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ pubkey32)[..4]`
//! (`0x01` = the Ed25519 algorithm byte). The signature is over the note's **text body** (origin / size /
//! base64 root / extensions), including its trailing newline.

use crate::canon::digest::sha256_array;
use crate::error::{Error, ErrorCode};
use crate::merkle::TreeHash;
use crate::sign::{Signature, Signer, VerifyingKey, verify};
use crate::wire::dec_u64;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

/// The signature-line prefix: em-dash (U+2014) + space. NOT a hyphen.
const EM_DASH_SP: &[u8] = b"\xe2\x80\x94 ";

/// A signed-tree-head checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// The log origin (first body line; no spaces).
    pub origin: String,
    /// The tree size.
    #[serde(with = "dec_u64")]
    pub size: u64,
    /// The tree root.
    pub root: TreeHash,
    /// Optional extension lines (after the root line).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub extensions: Vec<String>,
}

/// The deterministic note **text body**: `origin "\n" size "\n" base64(root) "\n" [ext "\n"]…`.
#[must_use]
pub fn checkpoint_body(c: &Checkpoint) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(c.origin.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(c.size.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(crate::base64::encode_std(c.root.as_bytes()).as_bytes());
    out.push(b'\n');
    for ext in &c.extensions {
        out.extend_from_slice(ext.as_bytes());
        out.push(b'\n');
    }
    out
}

/// The 4-byte note key-hash: `SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ pubkey32)[..4]`.
#[must_use]
pub fn key_hash(keyname: &str, vk: &VerifyingKey) -> [u8; 4] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(keyname.as_bytes());
    preimage.push(0x0A);
    preimage.push(0x01);
    preimage.extend_from_slice(&vk.to_bytes());
    let full = sha256_array(&preimage);
    let mut out = [0u8; 4];
    for (dst, src) in out.iter_mut().zip(full.iter()) {
        *dst = *src;
    }
    out
}

/// Sign a checkpoint body, appending the mandatory blank-line separator and one
/// `— <keyname> <base64(keyhash4 ‖ sig64)>` signature line (c2sp.org/signed-note). The signature is over `body`
/// (which already ends in a newline); the blank line that follows it is NOT signed.
#[must_use]
pub fn sign_checkpoint(
    body: &[u8],
    keyname: &str,
    vk: &VerifyingKey,
    signer: &dyn Signer,
) -> Vec<u8> {
    let signature = signer.sign(body);
    let mut blob = Vec::with_capacity(68);
    blob.extend_from_slice(&key_hash(keyname, vk));
    blob.extend_from_slice(&signature.0);
    let mut note = Vec::from(body);
    note.push(b'\n'); // the mandatory blank-line separator between the signed text and the signature block
    note.extend_from_slice(EM_DASH_SP);
    note.extend_from_slice(keyname.as_bytes());
    note.push(b' ');
    note.extend_from_slice(crate::base64::encode_std(&blob).as_bytes());
    note.push(b'\n');
    note
}

/// Split a C2SP signed note into its **signed text** and the trailing signature block at the mandatory
/// blank-line separator (c2sp.org/signed-note): `text` (ending in `\n`), then a blank line (a lone `\n`), then
/// ≥1 signature line. The returned signed text includes its final newline but NOT the separating blank line.
/// A checkpoint's text lines (origin / size / root / extensions) are all non-empty, so the FIRST `\n\n` is
/// unambiguously the separator. Returns `None` (→ fail closed) for a note with no blank-line separator.
fn split_note(note: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 0usize;
    loop {
        let j = i.checked_add(1)?;
        let (Some(&a), Some(&b)) = (note.get(i), note.get(j)) else {
            return None;
        };
        if a == b'\n' && b == b'\n' {
            let body = note.get(..=i)?; // through the first newline (the signed text)
            let sigs = note.get(j.checked_add(1)?..)?; // after the blank line
            return Some((body, sigs));
        }
        i = j;
    }
}

/// Verify a checkpoint note against a known key. Requires **≥1** signature line to match `keyname` with a correct
/// key-hash and a valid signature over the body (unknown lines are ignored, per the note spec).
///
/// # Errors
/// `CheckpointSignatureInvalid` if no signature matched, or the body is malformed.
pub fn verify_checkpoint(
    note: &[u8],
    keyname: &str,
    vk: &VerifyingKey,
) -> Result<Checkpoint, Error> {
    let (body, sig_block) =
        split_note(note).ok_or(Error::Signature(ErrorCode::CheckpointSignatureInvalid))?;
    let expected = key_hash(keyname, vk);

    let mut matched = false;
    for line in sig_block.split(|&b| b == b'\n') {
        let Some(after) = line.strip_prefix(EM_DASH_SP) else {
            continue;
        };
        let mut parts = after.split(|&b| b == b' ');
        let name = parts.next().unwrap_or_default();
        let blob_b64 = parts.next().unwrap_or_default();
        if name != keyname.as_bytes() {
            continue;
        }
        let Ok(blob_str) = core::str::from_utf8(blob_b64) else {
            continue;
        };
        let Some(blob) = crate::base64::decode_any(blob_str) else {
            continue;
        };
        if blob.len() != 68 {
            continue;
        }
        let (Some(kh), Some(sig_bytes)) = (blob.get(..4), blob.get(4..)) else {
            continue;
        };
        if kh != expected {
            continue;
        }
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
            continue;
        };
        if verify(vk, body, &Signature(sig_arr)).is_ok() {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err(Error::Signature(ErrorCode::CheckpointSignatureInvalid));
    }
    parse_checkpoint_body(body)
}

/// Parse a checkpoint text body into a [`Checkpoint`].
fn parse_checkpoint_body(body: &[u8]) -> Result<Checkpoint, Error> {
    let bad = || Error::Signature(ErrorCode::CheckpointSignatureInvalid);
    let mut lines = body.split(|&b| b == b'\n');
    let origin = core::str::from_utf8(lines.next().ok_or_else(bad)?)
        .map_err(|_| bad())?
        .to_string();
    let size = core::str::from_utf8(lines.next().ok_or_else(bad)?)
        .map_err(|_| bad())?
        .parse::<u64>()
        .map_err(|_| bad())?;
    let root_b64 = core::str::from_utf8(lines.next().ok_or_else(bad)?).map_err(|_| bad())?;
    let root_bytes = crate::base64::decode_any(root_b64).ok_or_else(bad)?;
    let root_arr = <[u8; 32]>::try_from(root_bytes.as_slice()).map_err(|_| bad())?;
    let mut extensions = Vec::new();
    for line in lines {
        if !line.is_empty() {
            extensions.push(core::str::from_utf8(line).map_err(|_| bad())?.to_string());
        }
    }
    Ok(Checkpoint {
        origin,
        size,
        root: TreeHash::from_bytes(root_arr),
        extensions,
    })
}
