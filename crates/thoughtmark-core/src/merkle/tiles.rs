// SPDX-License-Identifier: Apache-2.0
//! C2SP `tlog-tiles` primitives (arch §6.5).
//!
//! A tile is a run of consecutive subtree hashes at one level; a **full** tile is height-8 (256 hashes, 8192
//! bytes), and the last tile of a level may be partial. The on-disk index uses the `x`-prefixed three-digit-group
//! encoding (`1234067 → x001/x234/067`): split the decimal index into 3-digit groups, zero-padded on the left,
//! and prefix every group except the last with `x`. The injected-source `HashReader` that lets a thin verifier
//! fetch only O(log n) tiles lands with `TileStorage` (a later phase); core ships the pure parser + path encoder.

use crate::error::{Error, ErrorCode};
use crate::merkle::TreeHash;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

/// Bytes per hash.
const HASH_LEN: usize = 32;
/// A full height-8 tile holds 256 hashes.
const FULL_TILE_BYTES: usize = HASH_LEN * 256;

/// Parse a tile blob into its [`TreeHash`]es. Fail-closed on a length that is not a non-zero multiple of 32, or
/// that exceeds a full tile (256 hashes).
///
/// # Errors
/// `MerkleProofInvalid` for a malformed tile length.
pub fn parse_tile(bytes: &[u8]) -> Result<Vec<TreeHash>, Error> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(HASH_LEN) || bytes.len() > FULL_TILE_BYTES {
        return Err(Error::Inclusion(ErrorCode::MerkleProofInvalid));
    }
    let mut out = Vec::with_capacity(bytes.len().wrapping_div(HASH_LEN));
    for chunk in bytes.chunks_exact(HASH_LEN) {
        let arr = <[u8; 32]>::try_from(chunk)
            .map_err(|_| Error::Inclusion(ErrorCode::MerkleProofInvalid))?;
        out.push(TreeHash::from_bytes(arr));
    }
    Ok(out)
}

/// Encode a tile index as the `x`-prefixed three-digit-group path component (`1234067 → "x001/x234/067"`).
#[must_use]
pub fn tile_index_path(index: u64) -> String {
    let digits = index.to_string();
    let rem = digits.len().checked_rem(3).unwrap_or(0);
    let pad = if rem == 0 {
        0
    } else {
        3usize.saturating_sub(rem)
    };
    let mut padded = String::with_capacity(digits.len().saturating_add(pad));
    for _ in 0..pad {
        padded.push('0');
    }
    padded.push_str(&digits);

    let groups: Vec<&[u8]> = padded.as_bytes().chunks(3).collect();
    let last = groups.len().saturating_sub(1);
    let mut out = String::new();
    for (i, group) in groups.iter().enumerate() {
        if i != 0 {
            out.push('/');
        }
        if i != last {
            out.push('x');
        }
        if let Ok(g) = core::str::from_utf8(group) {
            out.push_str(g);
        }
    }
    out
}

/// The full tile path: `tile/<level>/<index-path>` (a partial tile appends `.p/<width>`, handled by storage).
#[must_use]
pub fn tile_path(level: u8, index: u64) -> String {
    let mut out = String::from("tile/");
    out.push_str(&level.to_string());
    out.push('/');
    out.push_str(&tile_index_path(index));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_path_uses_x_prefixed_groups() {
        // The architecture's worked example.
        assert_eq!(tile_index_path(1_234_067), "x001/x234/067");
        assert_eq!(tile_index_path(0), "000");
        assert_eq!(tile_index_path(67), "067");
        assert_eq!(tile_index_path(1_234), "x001/234");
        assert_eq!(tile_path(2, 1_234_067), "tile/2/x001/x234/067");
    }

    #[test]
    fn parse_tile_rejects_bad_lengths() {
        assert!(parse_tile(&[]).is_err());
        assert!(parse_tile(&[0u8; 31]).is_err());
        assert!(parse_tile(&[0u8; 33]).is_err());
        assert!(parse_tile(&[0u8; FULL_TILE_BYTES + 32]).is_err());
        assert_eq!(parse_tile(&[0u8; 64]).map(|v| v.len()), Ok(2));
    }
}
