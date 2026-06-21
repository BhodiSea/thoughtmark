// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    clippy::todo,
    clippy::float_arithmetic,
    clippy::string_slice
)]
//! `thoughtmark-core` — the pure, audited primitive.
//!
//! `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, no I/O, no clock, no RNG-source, no network. This crate and
//! [`thoughtmark-schema`](https://docs.rs/thoughtmark-schema) are the entire `no_std` island — precisely the
//! audited, byte-identical surface (arch §3.4).
//!
//! # Integrity, not validity
//!
//! This library proves **integrity-of-record** (a record existed at a time, in a lineage, unaltered since
//! capture; append-only consistency; signer identity). It does **not** prove validity, faithfulness, split-view
//! resistance, or truth-at-capture. See `docs/threat-model.md`.
//!
//! # Tier 0
//!
//! Phase 1 lands the deterministic byte foundation: [`canon`] (JCS canonicalization, hashing, content addressing,
//! domain separation, salted commitments) and the injected-determinism runtime [`determinism`]. [`ops::run_op`]
//! is the single string-dispatched seam shared byte-for-byte with the WASM binding.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod anchor;
mod base64;
pub mod bundle;
pub mod canon;
pub mod checkpoint;
pub mod determinism;
pub mod did_key;
pub mod dsse;
pub mod envelope;
pub mod error;
mod hex;
pub mod merkle;
pub mod ops;
pub mod scalar;
pub mod seam;
pub mod sign;
pub mod verify;
mod wire;

pub use anchor::{
    AnchorKind, AnchorReceipt, AnchorVerdict, AnchorVerifier, NoAnchorVerifier, VerifyParams,
};
pub use bundle::{BUNDLE_MEDIA_TYPE, BUNDLE_VERSION, ThoughtmarkBundle};
pub use canon::{
    CANON_VERSION, CanonError, Digest, HashAlg, canonicalize, canonicalize_str, hash, hash_domain,
    hash_with,
};
pub use checkpoint::{
    Checkpoint, checkpoint_body, count_checkpoint_cosignatures, parse_checkpoint, sign_checkpoint,
    verify_checkpoint,
};
pub use determinism::{Clock, Csprng, Rng, UnixMillis};
pub use did_key::{decode_did_key, encode_did_key};
pub use dsse::{DSSE_PAYLOAD_TYPE, DsseEnvelope, EnvSig, pae};
pub use error::{Error, ErrorCode, Result};
pub use merkle::{
    ConsistencyProof, InclusionProof, TreeHash, TreeState, merkle_tree_hash, verify_consistency,
    verify_inclusion,
};
pub use scalar::{
    Action, ApprovalScope, CanonVersion, PREDICATE_TYPE, ParticipantKind, STATEMENT_TYPE,
};
pub use seam::{AttestationKind, Attestor, IdentityResolver};
pub use sign::{Signature, Signer, TmSigner, VerifyingKey, verify, verify_envelope};
pub use verify::{
    CheckDetail, CheckKind, CheckOutcome, CheckStatus, Established, LineageStep, NotEstablished,
    Policy, PolicyWire, VerificationResult,
};
// The §11 orchestrator is re-exported as `verify_bundle` because the crate root already binds `verify` to the
// raw Ed25519 `sign::verify` primitive; the frozen §14.1 `verify` verb is `thoughtmark_core::verify::verify`.
pub use verify::verify as verify_bundle;
