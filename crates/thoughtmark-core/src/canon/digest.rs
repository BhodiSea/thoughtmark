// SPDX-License-Identifier: Apache-2.0
//! Hash algorithms and digests (arch §4.4).
//!
//! [`HashAlg`] is the audited algorithm set (BLAKE3 internal default, SHA-256 interop). [`Digest`] is a fixed
//! 32-byte digest tagged with its algorithm, with a **hand-written** serde shape `{"alg","bytes_hex"}` — a derived
//! serde would emit `bytes` as a 32-number array (reopening the no-array-of-ints concern, arch §4.4) and would not
//! match the vectors. Deserialization is fail-closed.

use crate::canon::error::CanonError;
use alloc::string::String;
use alloc::vec::Vec;

/// A content-hash algorithm. `#[non_exhaustive]` and append-only.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashAlg {
    /// BLAKE3-256 — the internal default.
    Blake3,
    /// SHA-256 — for interop with external systems.
    Sha256,
}

impl HashAlg {
    /// The multicodec multihash code: BLAKE3 = `0x1e`, SHA2-256 = `0x12`.
    #[must_use]
    pub const fn multihash_code(self) -> u64 {
        match self {
            HashAlg::Blake3 => 0x1e,
            HashAlg::Sha256 => 0x12,
        }
    }

    /// The digest length in bytes (always 32 for both algorithms).
    #[must_use]
    pub const fn digest_len(self) -> usize {
        32
    }

    /// The wire token: `"blake3"` or `"sha256"` (NOT `"sha2-256"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HashAlg::Blake3 => "blake3",
            HashAlg::Sha256 => "sha256",
        }
    }

    /// Parse a wire token back to a [`HashAlg`], or `None` for an unknown token.
    #[must_use]
    pub fn from_token(token: &str) -> Option<HashAlg> {
        match token {
            "blake3" => Some(HashAlg::Blake3),
            "sha256" => Some(HashAlg::Sha256),
            _ => None,
        }
    }
}

/// A 32-byte content digest tagged with the algorithm that produced it. `Copy`, no allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Digest {
    /// The algorithm that produced [`Digest::bytes`].
    pub alg: HashAlg,
    /// The raw 32-byte digest.
    pub bytes: [u8; 32],
}

impl Digest {
    /// The digest as 64 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        crate::hex::encode_lower(&self.bytes)
    }

    /// The canonical multihash bytes: `<code uvarint> <0x20 length> <32 digest bytes>`. Both multihash codes
    /// (`0x1e`/`0x12`) and the length (`0x20`) are `< 0x80`, so each is a single-byte unsigned varint. A unit test
    /// pins this against the `multihash` crate's canonical encoding (the cross-module invariant with `cid.rs`).
    #[must_use]
    pub fn multihash_bytes(&self) -> Vec<u8> {
        let code_byte: u8 = match self.alg {
            HashAlg::Blake3 => 0x1e,
            HashAlg::Sha256 => 0x12,
        };
        let mut out = Vec::with_capacity(34);
        out.push(code_byte);
        out.push(0x20);
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Construct a [`Digest`] from its wire parts, fail-closed: an unknown `alg` token → `UnknownHashAlg`; a
    /// `bytes_hex` whose length ≠ 64 or which is not lowercase hex → `InvalidJson`.
    ///
    /// # Errors
    /// Returns a [`CanonError`] if `alg` is unknown or `bytes_hex` is malformed.
    pub fn from_parts(alg: &str, bytes_hex: &str) -> Result<Digest, CanonError> {
        let alg = HashAlg::from_token(alg).ok_or(CanonError::UnknownHashAlg)?;
        if bytes_hex.len() != 64 {
            return Err(CanonError::InvalidJson);
        }
        let decoded = crate::hex::decode(bytes_hex).ok_or(CanonError::InvalidJson)?;
        let bytes =
            <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| CanonError::InvalidJson)?;
        Ok(Digest { alg, bytes })
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut st = serializer.serialize_struct("Digest", 2)?;
        st.serialize_field("alg", self.alg.as_str())?;
        st.serialize_field("bytes_hex", &self.to_hex())?;
        st.end()
    }
}

/// Intermediate wire shape; the real validation lives in [`Digest::from_parts`].
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestWire {
    alg: String,
    bytes_hex: String,
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = DigestWire::deserialize(deserializer)?;
        // Carry the specific ErrorCode token in the serde error message so it stays fail-closed and recoverable.
        Digest::from_parts(&wire.alg, &wire.bytes_hex)
            .map_err(|e| serde::de::Error::custom(crate::error::ErrorCode::from(e).as_str()))
    }
}

/// Hash `bytes` with `alg`.
#[must_use]
pub fn hash_with(alg: HashAlg, bytes: &[u8]) -> Digest {
    let out = match alg {
        HashAlg::Blake3 => *blake3::hash(bytes).as_bytes(),
        HashAlg::Sha256 => sha256_array(bytes),
    };
    Digest { alg, bytes: out }
}

/// Hash `bytes` with the internal default (BLAKE3).
#[must_use]
pub fn hash(bytes: &[u8]) -> Digest {
    hash_with(HashAlg::Blake3, bytes)
}

/// SHA-256 into a fixed array. The output length is statically 32, so the `copy_from_slice` cannot panic (it runs
/// only behind the length guard); the impossible mismatch leaves a zeroed array rather than panicking.
fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let computed = sha2::Sha256::digest(bytes);
    let mut out = [0u8; 32];
    let src = computed.as_slice();
    if src.len() == 32 {
        out.copy_from_slice(src);
    }
    out
}
