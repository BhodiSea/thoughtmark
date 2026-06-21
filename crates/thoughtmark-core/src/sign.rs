// SPDX-License-Identifier: Apache-2.0
//! Ed25519 signing and verification (arch §7.3, §7.4, ADR-0007, I6).
//!
//! Verification is **`verify_strict` ALWAYS** (a clippy `disallowed-methods` lint bans bare `verify`): it rejects
//! small-order `A`/`R` and non-canonical `S`, killing the cofactor-8 malleability that would otherwise yield two
//! valid signatures per message and corrupt Merkle-leaf stability. The [`Signer`] trait is the seam the
//! log/checkpoint layers use, so key material never enters them. [`TmSigner`] holds its 32-byte seed in a
//! `secrecy::SecretBox` (zeroized on drop) and is deliberately never `Debug`/`Clone`/`Serialize`. Core mints keys
//! only via [`TmSigner::from_seed`] (a caller-supplied seed) and links no CSPRNG at all — the RNG-injecting helper
//! is left to the host/reference app (the `keygen` feature is reserved/inert). There is no secret-adjacent equality
//! compare in this module, so the audited verify path needs neither a CSPRNG nor a `subtle` constant-time compare;
//! the seed lives in a `SecretBox` and the transient `SigningKey` reconstructed in `sign` zeroizes on drop.

use crate::dsse::{DSSE_PAYLOAD_TYPE, DsseEnvelope, EnvSig, pae};
use crate::error::{Error, ErrorCode};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use ed25519_dalek::Signer as _;
use secrecy::{ExposeSecret as _, SecretBox};
use zeroize::Zeroize as _;

/// An Ed25519 public key (validated on-curve at construction).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Construct from 32 raw bytes, fail-closed on an off-curve / malformed key.
    ///
    /// # Errors
    /// `SigMalformedKey` if the bytes are not a valid Ed25519 point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, Error> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|_| Error::Signature(ErrorCode::SigMalformedKey))
    }

    /// The 32 raw public-key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy)]
pub struct Signature(pub [u8; 64]);

/// The signing seam: log/checkpoint code takes a `&dyn Signer`, so key material never enters those layers.
pub trait Signer {
    /// The signer's key id (a DID verificationMethod URL → the DSSE `keyid`).
    fn key_id(&self) -> &str;
    /// Sign a message (the PAE bytes), returning a 64-byte Ed25519 signature.
    fn sign(&self, msg: &[u8]) -> Signature;
}

/// A private signer: a 32-byte seed in a zeroized `SecretBox`, plus the derived public key and key id. Never
/// `Debug`/`Clone`/`Serialize` — the seed cannot leak through a trait impl.
pub struct TmSigner {
    seed: SecretBox<[u8; 32]>,
    public: VerifyingKey,
    key_id: String,
}

impl TmSigner {
    /// Build a signer from a 32-byte seed and key id. Deterministic; needs no RNG. The caller's `seed` copy is
    /// zeroized before returning.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32], key_id: String) -> TmSigner {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = VerifyingKey(signing.verifying_key());
        let boxed = SecretBox::new(Box::new(seed));
        seed.zeroize();
        TmSigner {
            seed: boxed,
            public,
            key_id,
        }
    }

    /// The signer's public key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.public
    }

    /// Wrap a raw payload in a DSSE envelope: `pae(DSSE_PAYLOAD_TYPE, payload)`, signed once (ADR-0007).
    #[must_use]
    pub fn sign_payload(&self, payload: &[u8]) -> DsseEnvelope {
        let pae_bytes = pae(DSSE_PAYLOAD_TYPE, payload);
        let signature = self.sign(&pae_bytes);
        DsseEnvelope {
            payload: crate::base64::encode_std(payload),
            payload_type: String::from(DSSE_PAYLOAD_TYPE),
            signatures: vec![EnvSig {
                keyid: self.key_id.clone(),
                sig: crate::base64::encode_std(&signature.0),
            }],
        }
    }
}

impl Signer for TmSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        // Reconstruct the signing key transiently (it zeroizes on drop); Ed25519 signing is deterministic.
        let signing = ed25519_dalek::SigningKey::from_bytes(self.seed.expose_secret());
        Signature(signing.sign(msg).to_bytes())
    }
}

/// Verify a detached signature over `msg` with `verify_strict` (the only sanctioned path).
///
/// # Errors
/// `SigInvalid` if the signature does not verify strictly.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.0.verify_strict(msg, &dalek_sig)
        .map_err(|_| Error::Signature(ErrorCode::SigInvalid))
}

/// Verify a DSSE envelope against a set of candidate keys, returning the raw (decoded) payload bytes on success.
/// Requires the `payloadType` to match and **at least one** signature to verify (ADR-0007).
///
/// # Errors
/// `DssePayloadTypeMismatch` / `DsseBadEnvelope` for structural problems; `SigInvalid` if no signature verifies.
pub fn verify_envelope(env: &DsseEnvelope, keys: &[VerifyingKey]) -> Result<Vec<u8>, Error> {
    if env.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(Error::Dsse(ErrorCode::DssePayloadTypeMismatch));
    }
    let payload =
        crate::base64::decode_any(&env.payload).ok_or(Error::Dsse(ErrorCode::DsseBadEnvelope))?;
    let pae_bytes = pae(&env.payload_type, &payload);
    for envsig in &env.signatures {
        let Some(sig_bytes) = crate::base64::decode_any(&envsig.sig) else {
            continue;
        };
        let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            continue;
        };
        let signature = Signature(arr);
        for vk in keys {
            if verify(vk, &pae_bytes, &signature).is_ok() {
                return Ok(payload);
            }
        }
    }
    Err(Error::Signature(ErrorCode::SigInvalid))
}
