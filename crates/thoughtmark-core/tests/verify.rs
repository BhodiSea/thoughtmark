// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the §11 `verify()` pipeline. Drives the public Rust API directly over the blessed
//! `spec/vectors/verify/*` fixtures (no duplication of the bundle builder), asserting the orchestrator's
//! structural invariants that the byte-pinned vectors back: fixed check order, value-not-error, the constant
//! `NotEstablished` frame, tamper independence, and determinism.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use proptest::prelude::*;
use std::path::PathBuf;
use thoughtmark_core::{
    CheckKind, CheckStatus, Clock, NoAnchorVerifier, Policy, PolicyWire, ThoughtmarkBundle,
    UnixMillis, VerificationResult, canonicalize, verify_bundle,
};

struct TestClock(i64);
impl Clock for TestClock {
    fn now(&self) -> UnixMillis {
        UnixMillis(self.0)
    }
}

/// Load a blessed `verify/<name>/input.json` fixture into the runtime `(bundle, policy, now)`.
fn load(name: &str) -> (ThoughtmarkBundle, Policy, i64) {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "../../spec/vectors/verify",
        name,
        "input.json",
    ]
    .iter()
    .collect();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // Deserialize via `from_slice` (not `from_value`): the bundle's borrowed-`&str` adapters
    // (`bytes_b64`/`dec_u64`/`TreeHash`) cannot borrow from an owned `serde_json::Value`.
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    let policy = input.policy.into_policy().unwrap();
    (input.bundle, policy, input.env.now_unix_ms.0)
}

/// The fixture input shape (mirrors the `verify` op's request).
#[derive(serde::Deserialize)]
struct Input {
    bundle: ThoughtmarkBundle,
    policy: PolicyWire,
    env: Env,
}
#[derive(serde::Deserialize)]
struct Env {
    now_unix_ms: UnixMillis,
}

fn run(name: &str) -> VerificationResult {
    let (bundle, policy, now) = load(name);
    verify_bundle(&bundle, &policy, &TestClock(now), &NoAnchorVerifier)
}

#[test]
fn all_pass_establishes_full_lineage() {
    let r = run("0001");
    assert!(r.total, "all-pass fixture must verify");
    assert!(r.established.unaltered_since_capture);
    let lineage = r.established.lineage.expect("lineage populated on pass");
    assert_eq!(lineage.len(), 2, "two ledger contributions");
    assert_eq!(lineage[0].action, thoughtmark_core::Action::Create);
    assert_eq!(lineage[1].action, thoughtmark_core::Action::Approve);
    assert!(r.established.bound_subject_digest.is_some());
    assert_eq!(r.established.signed_by.len(), 1);
    assert_eq!(
        r.established.log_origin.as_deref(),
        Some("thoughtmark.dev/log/bundle-demo")
    );
}

#[test]
fn checks_are_always_in_fixed_order() {
    for name in ["0001", "0002", "0003", "0004"] {
        let r = run(name);
        let kinds: Vec<CheckKind> = r.checks.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            CheckKind::ORDER.to_vec(),
            "{name}: fixed CheckKind order"
        );
        assert_eq!(r.checks.len(), 9);
    }
}

#[test]
fn tamper_fails_one_check_but_report_survives() {
    let r = run("0002");
    assert!(!r.total, "a tampered signature must not pass");
    assert!(!r.established.unaltered_since_capture);
    let dsse = r
        .checks
        .iter()
        .find(|c| c.kind == CheckKind::DsseSignature)
        .unwrap();
    assert_eq!(dsse.status, CheckStatus::Fail);
    // One failure never masks another: the intact record still binds and includes.
    let binding = r
        .checks
        .iter()
        .find(|c| c.kind == CheckKind::StatementBinding)
        .unwrap();
    let merkle = r
        .checks
        .iter()
        .find(|c| c.kind == CheckKind::MerkleInclusion)
        .unwrap();
    assert_eq!(binding.status, CheckStatus::Pass);
    assert_eq!(merkle.status, CheckStatus::Pass);
}

#[test]
fn require_anchor_fails_closed_at_phase_3() {
    let r = run("0003");
    assert!(!r.total);
    let anchor = r
        .checks
        .iter()
        .find(|c| c.kind == CheckKind::AnchorReceipt)
        .unwrap();
    assert_eq!(anchor.status, CheckStatus::Fail);
    assert!(
        r.established.existed_at_or_before.is_none(),
        "no time bound without a verifier"
    );
}

#[test]
fn unmet_required_action_fails_lineage() {
    let r = run("0004");
    assert!(!r.total);
    let lineage = r
        .checks
        .iter()
        .find(|c| c.kind == CheckKind::ContributionLineage)
        .unwrap();
    assert_eq!(lineage.status, CheckStatus::Fail);
    assert_eq!(
        lineage.code,
        Some(thoughtmark_core::ErrorCode::PolicyUnsatisfied)
    );
    assert!(
        r.established.lineage.is_none(),
        "lineage not populated on fail"
    );
}

#[test]
fn not_established_is_a_byte_constant() {
    // The honesty frame is identical bytes for every run (the I7 guarantee).
    let a = canonicalize(&run("0001").not_established).unwrap();
    let b = canonicalize(&run("0002").not_established).unwrap();
    assert_eq!(a, b);
    let s = String::from_utf8(a).unwrap();
    assert!(s.contains("validity_of_record"));
    assert!(s.contains("authorship_truth"));
}

proptest! {
    /// The result is fully deterministic: the same inputs yield byte-identical canonical bytes, and the only
    /// timestamp is the injected `now`.
    #[test]
    fn verify_is_deterministic(now in any::<i64>()) {
        let (bundle, policy, _) = load("0001");
        let r1 = verify_bundle(&bundle, &policy, &TestClock(now), &NoAnchorVerifier);
        let r2 = verify_bundle(&bundle, &policy, &TestClock(now), &NoAnchorVerifier);
        prop_assert_eq!(canonicalize(&r1).unwrap(), canonicalize(&r2).unwrap());
        prop_assert_eq!(r1.verified_at, UnixMillis(now));
    }
}

proptest! {
    /// Tamper monotonicity: corrupting ANY single byte of the checkpoint's SIGNED TEXT (origin / size / root,
    /// before the blank-line separator) ALWAYS flips the verdict to `false` — every such byte is covered by the
    /// checkpoint signature, so the `Checkpoint` (and usually `MerkleInclusion`) check fails — while the report
    /// shape (nine checks, fixed order) and the constant `NotEstablished` honesty frame (I7) are never disturbed,
    /// and `total` always equals the AND over non-`Skipped` checks.
    ///
    /// The flip is confined to the signed text deliberately: the base64 SIGNATURE line after the separator has
    /// redundant bits, so a flip there can decode identically (a no-op) — the signature line is not itself signed.
    #[test]
    fn one_byte_checkpoint_body_tamper_always_flips_total(idx in 0usize..100_000, delta in 1u8..=255) {
        let (mut bundle, policy, now) = load("0001");
        // The signed text runs up to (and including the first `\n` of) the `\n\n` blank-line separator.
        let sep = bundle
            .checkpoint
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("a C2SP checkpoint note has a blank-line separator");
        let body_len = sep + 1;
        bundle.checkpoint[idx % body_len] ^= delta;
        let r = verify_bundle(&bundle, &policy, &TestClock(now), &NoAnchorVerifier);
        prop_assert!(!r.total, "a corrupted checkpoint body must never verify");
        prop_assert_eq!(r.checks.len(), 9);
        let kinds: Vec<CheckKind> = r.checks.iter().map(|c| c.kind).collect();
        prop_assert_eq!(kinds, CheckKind::ORDER.to_vec());
        // total == AND over the required (non-Skipped) checks.
        prop_assert_eq!(r.total, r.checks.iter().all(|c| c.status != CheckStatus::Fail));
        // The honesty frame is byte-constant regardless of the verdict.
        let pristine = run("0001");
        prop_assert_eq!(
            canonicalize(&r.not_established).unwrap(),
            canonicalize(&pristine.not_established).unwrap()
        );
    }
}

proptest! {
    /// The result algebra holds for the intact bundle at any injected `now`: `total` is the AND over non-`Skipped`
    /// checks, and `unaltered_since_capture` is exactly `DsseSignature && StatementBinding && MerkleInclusion &&
    /// Checkpoint` (§11.3).
    #[test]
    fn total_and_unaltered_algebra(now in any::<i64>()) {
        let (bundle, policy, _) = load("0001");
        let r = verify_bundle(&bundle, &policy, &TestClock(now), &NoAnchorVerifier);
        let status = |k| r.checks.iter().find(|c| c.kind == k).map(|c| c.status);
        let four = status(CheckKind::DsseSignature) == Some(CheckStatus::Pass)
            && status(CheckKind::StatementBinding) == Some(CheckStatus::Pass)
            && status(CheckKind::MerkleInclusion) == Some(CheckStatus::Pass)
            && status(CheckKind::Checkpoint) == Some(CheckStatus::Pass);
        prop_assert_eq!(r.established.unaltered_since_capture, four);
        prop_assert_eq!(r.total, r.checks.iter().all(|c| c.status != CheckStatus::Fail));
    }
}
