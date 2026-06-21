// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `thoughtmark-log` — the append-only transparency-log storage shell (arch §6.5).
//!
//! `std`, and **never imported by `thoughtmark-core`** (the dependency-direction invariant, I8 — the CI check
//! lists it among the crates forbidden in core's closure). All Merkle hashing delegates to
//! [`thoughtmark_core::merkle`], so the roots and proofs this layer serves are byte-identical to what the pure
//! offline verifier recomputes — that delegation is the whole point of the crate boundary.
//!
//! The one hard correctness property is **gap-free, monotonically increasing indices**: a gap or duplicate index
//! silently corrupts every later root. The pure [`sequencer`] logic enforces it (proptested under simulated
//! concurrent appends); the `PostgresStorage` driver that binds it to `pg_advisory_xact_lock` ships with the
//! reference app (a later phase). Only the trait + [`InMemoryStorage`] + the sequencer land here.

pub mod memory;
pub mod sequencer;
pub mod storage;

pub use memory::InMemoryStorage;
pub use sequencer::{SequenceError, next_index};
pub use storage::{LogStorage, StorageError};
