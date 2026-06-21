// SPDX-License-Identifier: Apache-2.0
//! The offline `verify()` orchestrator (arch §11).
//!
//! Composes every Tier-0/Tier-1 primitive into a single pure function over the bytes stapled in a
//! [`ThoughtmarkBundle`] — no socket opened, no ambient clock. The clock is read **exactly once** at entry; each
//! of the nine checks runs **independently** (one failure never masks another) in the fixed, byte-stable
//! [`CheckKind::ORDER`]; `total` is the AND of all REQUIRED (non-`Skipped`) checks. The function returns a
//! [`VerificationResult`] **value, never `Result`** (§10.3): a tamper is a successful run with `total = false`, so
//! the full proven/not-proven report — including the constant [`NotEstablished`] honesty frame (I7) — always
//! reaches the caller. `Err`/`JsError` is reserved for malformed INPUT, handled at the op boundary.

mod checks;
mod lineage;
pub mod policy;
pub mod result;
mod statement;

pub use policy::{Policy, PolicyWire};
pub use result::{
    CheckDetail, CheckKind, CheckOutcome, CheckStatus, Established, LineageStep, NotEstablished,
    VERIFICATION_RESULT_SCHEMA, VerificationResult,
};

use crate::anchor::AnchorVerifier;
use crate::bundle::ThoughtmarkBundle;
use crate::determinism::Clock;
use alloc::string::String;
use checks::Ctx;

/// Verify a [`ThoughtmarkBundle`] offline against a [`Policy`], an injected [`Clock`], and an injected
/// [`AnchorVerifier`] (arch §11.2). Reads `clock.now()` once; runs every check independently in
/// [`CheckKind::ORDER`]; returns the verdict + full report as a value.
#[must_use]
pub fn verify(
    bundle: &ThoughtmarkBundle,
    policy: &Policy,
    clock: &dyn Clock,
    anchors: &dyn AnchorVerifier,
) -> VerificationResult {
    let now = clock.now();
    let mut ctx = Ctx::new();
    // Structurally parse the checkpoint once (no signature check) so MerkleInclusion can read the root
    // independently of the Checkpoint signature check.
    ctx.checkpoint = crate::checkpoint::parse_checkpoint(&bundle.checkpoint).ok();

    let bundle_schema = checks::check_bundle_schema(bundle);
    let canon_version = checks::check_canon_version(bundle, policy);
    let dsse = checks::check_dsse_signature(bundle, policy, &mut ctx);
    let statement_binding = checks::check_statement_binding(bundle, policy, &mut ctx);
    let merkle = checks::check_merkle_inclusion(bundle, &ctx);
    let checkpoint = checks::check_checkpoint(bundle, policy);
    let consistency = checks::check_consistency(bundle);
    let (anchor, existed_at_or_before) = checks::check_anchor_receipt(bundle, policy, anchors, now);
    let (lineage_outcome, lineage_steps) = checks::check_contribution_lineage(bundle, policy, &ctx);

    // Capture the statuses that feed `established` before the outcomes move into the result vec.
    let st_dsse = dsse.status;
    let st_binding = statement_binding.status;
    let st_merkle = merkle.status;
    let st_checkpoint = checkpoint.status;

    // Emit in the fixed CheckKind order (the vec is built positionally, never by evaluation/push order).
    let checks_vec = alloc::vec![
        bundle_schema,
        canon_version,
        dsse,
        statement_binding,
        merkle,
        checkpoint,
        consistency,
        anchor,
        lineage_outcome,
    ];

    // `total` = no REQUIRED check failed (Skipped is neutral).
    let total = checks_vec.iter().all(|c| c.status != CheckStatus::Fail);

    let unaltered_since_capture = st_dsse == CheckStatus::Pass
        && st_binding == CheckStatus::Pass
        && st_merkle == CheckStatus::Pass
        && st_checkpoint == CheckStatus::Pass;

    let log_origin = if st_checkpoint == CheckStatus::Pass {
        ctx.checkpoint.as_ref().map(|c| c.origin.clone())
    } else {
        None
    };

    let established = Established {
        existed_at_or_before,
        unaltered_since_capture,
        lineage: lineage_steps,
        bound_subject_digest: ctx.bound_subject_digest,
        signed_by: ctx.signed_by,
        log_origin,
    };

    VerificationResult {
        schema: String::from(VERIFICATION_RESULT_SCHEMA),
        verified_at: now,
        total,
        checks: checks_vec,
        established,
        not_established: NotEstablished,
    }
}
