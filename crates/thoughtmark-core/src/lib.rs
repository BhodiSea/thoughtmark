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
//! # Phase 0 status
//!
//! Every operation is a stub returning [`ErrorCode::NotImplemented`]; [`ops::run_op`] maps that to the canonical
//! `NOT_IMPLEMENTED` envelope ([`envelope::error_envelope`]) so the cross-language byte-identity gate runs before
//! any real logic lands.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod envelope;
pub mod error;
pub mod ops;

pub use error::{Error, ErrorCode};
