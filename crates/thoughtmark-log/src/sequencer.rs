// SPDX-License-Identifier: Apache-2.0
//! The pure gap-free index sequencer (arch §6.5, §15.2).
//!
//! Append assigns the next index as exactly the current tree size, under an **optimistic-concurrency guard**: a
//! writer that observed `expected_size` may only commit if the log is still at that size. Two concurrent writers
//! who both observed size N race; exactly one wins (its append makes the size N+1), and the loser's guard fails
//! (`expected_size = N` ≠ `current_size = N+1`) and must retry. This is the storage-agnostic core of what
//! `pg_advisory_xact_lock(hashtext(log_id))` enforces at the database layer — guaranteeing indices are gap-free
//! and strictly monotonic, so no two leaves ever share an index and no index is skipped.

/// A sequencing conflict: the log advanced since the writer observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sequencer conflict: expected size {expected}, log is at {current} (retry)")]
pub struct SequenceError {
    /// The size the writer observed.
    pub expected: u64,
    /// The size the log is actually at now.
    pub current: u64,
}

/// Assign the next leaf index, given the size the writer observed (`expected`) and the log's actual current size.
///
/// Returns the index to write (== `current`) on success. Fails closed if the writer's view is stale, so a gap or
/// duplicate can never be committed.
///
/// # Errors
/// [`SequenceError`] if `expected != current`.
pub const fn next_index(expected: u64, current: u64) -> Result<u64, SequenceError> {
    if expected == current {
        Ok(current)
    } else {
        Err(SequenceError { expected, current })
    }
}
