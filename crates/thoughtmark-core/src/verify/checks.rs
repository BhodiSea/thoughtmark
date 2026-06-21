// SPDX-License-Identifier: Apache-2.0
//! The nine independent checks (arch §11.2).
//!
//! Each check is a pure function returning exactly one [`CheckOutcome`]; a check whose precondition is absent
//! returns its own `Fail`, never panicking or short-circuiting the run, so "one failure never masks another"
//! holds. Checks deposit reusable work (the decoded payload, the parsed statement/checkpoint, the verified
//! keyids) into a shared [`Ctx`] without coupling their verdicts.

use crate::anchor::{AnchorVerdict, AnchorVerifier, VerifyParams};
use crate::bundle::{ThoughtmarkBundle, VerificationMethod};
use crate::canon::domain::OBJECT;
use crate::canon::{self, Digest, HashAlg, hash_domain};
use crate::checkpoint::{Checkpoint, count_checkpoint_cosignatures};
use crate::determinism::UnixMillis;
use crate::dsse::{DSSE_PAYLOAD_TYPE, pae};
use crate::error::{Error, ErrorCode};
use crate::scalar::{CanonVersion, PREDICATE_TYPE, STATEMENT_TYPE};
use crate::sign::{self, Signature, VerifyingKey};
use crate::verify::lineage;
use crate::verify::policy::Policy;
use crate::verify::result::{CheckDetail, CheckKind, CheckOutcome, CheckStatus, LineageStep};
use crate::verify::statement::{StatementView, TrailView};
use alloc::string::String;
use alloc::vec::Vec;

/// Reusable work shared between checks (each check stays independent in *verdict*).
pub(crate) struct Ctx {
    /// The decoded DSSE payload bytes (the canonical Statement), once `DsseSignature` decodes them.
    pub payload: Option<Vec<u8>>,
    /// The parsed Statement view.
    pub statement: Option<StatementView>,
    /// The checkpoint parsed from the bundle (structurally, before signature verification).
    pub checkpoint: Option<Checkpoint>,
    /// The keyids whose signature verified under a trusted key.
    pub signed_by: Vec<String>,
    /// The subject digest `StatementBinding` bound (on pass).
    pub bound_subject_digest: Option<Digest>,
}

impl Ctx {
    pub(crate) fn new() -> Ctx {
        Ctx {
            payload: None,
            statement: None,
            checkpoint: None,
            signed_by: Vec::new(),
            bound_subject_digest: None,
        }
    }
}

fn outcome(
    kind: CheckKind,
    status: CheckStatus,
    code: Option<ErrorCode>,
    detail: Option<CheckDetail>,
) -> CheckOutcome {
    CheckOutcome {
        kind,
        status,
        code,
        detail,
    }
}

fn pass(kind: CheckKind) -> CheckOutcome {
    outcome(kind, CheckStatus::Pass, None, None)
}
fn pass_detail(kind: CheckKind, detail: CheckDetail) -> CheckOutcome {
    let d = if detail.is_empty() {
        None
    } else {
        Some(detail)
    };
    outcome(kind, CheckStatus::Pass, None, d)
}
fn fail(kind: CheckKind, code: ErrorCode) -> CheckOutcome {
    outcome(kind, CheckStatus::Fail, Some(code), None)
}
fn fail_detail(kind: CheckKind, code: ErrorCode, detail: CheckDetail) -> CheckOutcome {
    let d = if detail.is_empty() {
        None
    } else {
        Some(detail)
    };
    outcome(kind, CheckStatus::Fail, Some(code), d)
}
fn skipped(kind: CheckKind) -> CheckOutcome {
    outcome(kind, CheckStatus::Skipped, None, None)
}

/// `BundleSchema` — the structural shape gate.
pub(crate) fn check_bundle_schema(bundle: &ThoughtmarkBundle) -> CheckOutcome {
    match bundle.validate_shape() {
        Ok(()) => pass(CheckKind::BundleSchema),
        Err(e) => fail(CheckKind::BundleSchema, e.code()),
    }
}

/// `CanonVersion` — the bundle's canon version must parse and be policy-accepted (fail-closed).
pub(crate) fn check_canon_version(bundle: &ThoughtmarkBundle, policy: &Policy) -> CheckOutcome {
    match CanonVersion::parse(&bundle.canon_version) {
        Some(v) if policy.accepted_canon_versions.contains(&v) => pass(CheckKind::CanonVersion),
        _ => fail(CheckKind::CanonVersion, ErrorCode::UnknownCanonVersion),
    }
}

/// Resolve a verification method's public key (a `z`-multibase did:key suffix, or 64-hex).
fn resolve_method(method: &VerificationMethod) -> Result<VerifyingKey, Error> {
    let mb = method.public_key_multibase.as_str();
    if mb.starts_with('z') {
        let mut did = String::from("did:key:");
        did.push_str(mb);
        crate::did_key::decode_did_key(&did)
    } else {
        let bytes = crate::hex::decode(mb).ok_or(Error::Signature(ErrorCode::SigMalformedKey))?;
        let arr = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| Error::Signature(ErrorCode::SigMalformedKey))?;
        VerifyingKey::from_bytes(&arr)
    }
}

/// `DsseSignature` — verify the envelope under a trusted key, decode the payload, parse the Statement.
pub(crate) fn check_dsse_signature(
    bundle: &ThoughtmarkBundle,
    policy: &Policy,
    ctx: &mut Ctx,
) -> CheckOutcome {
    let env = &bundle.envelope;
    if env.payload_type != DSSE_PAYLOAD_TYPE {
        return fail(CheckKind::DsseSignature, ErrorCode::DssePayloadTypeMismatch);
    }
    let Some(payload) = crate::base64::decode_any(&env.payload) else {
        return fail(CheckKind::DsseSignature, ErrorCode::DsseBadEnvelope);
    };
    let pae_bytes = pae(&env.payload_type, &payload);

    let mut signed_by: Vec<String> = Vec::new();
    for envsig in &env.signatures {
        let Some(method) = bundle
            .verification_material
            .verification_methods
            .iter()
            .find(|m| m.id == envsig.keyid)
        else {
            continue;
        };
        let Ok(vk) = resolve_method(method) else {
            continue;
        };
        if !policy.trusted_keys.iter().any(|t| t == &vk) {
            continue;
        }
        let Some(sig_bytes) = crate::base64::decode_any(&envsig.sig) else {
            continue;
        };
        let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            continue;
        };
        if sign::verify(&vk, &pae_bytes, &Signature(arr)).is_ok()
            && !signed_by.contains(&envsig.keyid)
        {
            signed_by.push(envsig.keyid.clone());
        }
    }

    // The decoded payload is available to MerkleInclusion regardless of the signature verdict.
    ctx.payload = Some(payload.clone());
    ctx.signed_by.clone_from(&signed_by);

    // Parse the Statement INDEPENDENT of the signature verdict, so StatementBinding / MerkleInclusion /
    // ContributionLineage replay the intact record even when only the signature was tampered (checks stay
    // independent — one failure never masks another).
    let parsed = serde_json::from_slice::<StatementView>(&payload)
        .ok()
        .filter(|s| s.type_ == STATEMENT_TYPE && s.predicate_type == PREDICATE_TYPE);
    let statement_ok = parsed.is_some();
    ctx.statement = parsed;

    if signed_by.is_empty() {
        return fail(CheckKind::DsseSignature, ErrorCode::SigInvalid);
    }
    if !statement_ok {
        return fail(CheckKind::DsseSignature, ErrorCode::PredicateSchemaInvalid);
    }
    pass(CheckKind::DsseSignature)
}

/// Parse `"trail:<trail_id>@<tree_size>"`.
fn parse_subject_name(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("trail:")?;
    let at = rest.rfind('@')?;
    let num = rest.get(at.checked_add(1)?..)?;
    if !crate::wire::dec_u64::is_canonical(num) {
        return None;
    }
    num.parse::<u64>().ok()
}

/// `StatementBinding` — the subject digest equals the recomputed `trail_root`; the bound tree size matches.
pub(crate) fn check_statement_binding(
    bundle: &ThoughtmarkBundle,
    policy: &Policy,
    ctx: &mut Ctx,
) -> CheckOutcome {
    let Some(statement) = &ctx.statement else {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::PredicateSchemaInvalid,
        );
    };
    let Ok(canon_bytes) = canon::canonicalize_value(&statement.predicate) else {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::PredicateSchemaInvalid,
        );
    };
    let blake3 = hash_domain(HashAlg::Blake3, OBJECT, &canon_bytes);
    let sha256 = hash_domain(HashAlg::Sha256, OBJECT, &canon_bytes);
    let b3_hex = blake3.to_hex();
    let s256_hex = sha256.to_hex();

    // A thoughtmark Statement attests EXACTLY ONE trail-prefix subject. Validating only `subject[0]` while
    // `Established` reads as fully bound would over-claim integrity over unvalidated subjects (I7) — reject any
    // other arity rather than silently ignoring the tail.
    if statement.subject.len() != 1 {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::StatementSubjectMismatch,
        );
    }
    let Some(subject) = statement.subject.first() else {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::StatementSubjectMismatch,
        );
    };
    if subject.digest.get("blake3") != Some(&b3_hex)
        || subject.digest.get("sha256") != Some(&s256_hex)
    {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::StatementSubjectMismatch,
        );
    }
    if let Some(expected) = &policy.expected_subject_digest {
        let matches = match expected.alg {
            HashAlg::Blake3 => expected.to_hex() == b3_hex,
            HashAlg::Sha256 => expected.to_hex() == s256_hex,
        };
        if !matches {
            return fail(
                CheckKind::StatementBinding,
                ErrorCode::StatementSubjectMismatch,
            );
        }
    }
    let Some(tree_size) = parse_subject_name(&subject.name) else {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::StatementSubjectMismatch,
        );
    };
    if tree_size != bundle.inclusion.tree_size {
        return fail(
            CheckKind::StatementBinding,
            ErrorCode::StatementSubjectMismatch,
        );
    }

    ctx.bound_subject_digest = Some(blake3);
    pass_detail(
        CheckKind::StatementBinding,
        CheckDetail {
            tree_size: Some(tree_size),
            ..CheckDetail::empty()
        },
    )
}

/// `MerkleInclusion` — the statement leaf is in the tree rooted at the (structurally parsed) checkpoint root.
pub(crate) fn check_merkle_inclusion(bundle: &ThoughtmarkBundle, ctx: &Ctx) -> CheckOutcome {
    let (Some(payload), Some(checkpoint)) = (&ctx.payload, &ctx.checkpoint) else {
        return fail(CheckKind::MerkleInclusion, ErrorCode::MerkleProofInvalid);
    };
    let leaf = crate::merkle::hash_leaf(payload);
    if let Err(e) = crate::merkle::verify_inclusion(&bundle.inclusion, &leaf, &checkpoint.root) {
        return fail(CheckKind::MerkleInclusion, e.code());
    }
    // Defense-in-depth: the SIGNED checkpoint size must equal the proof's claimed tree size. The root already binds
    // this cryptographically (a different size cannot reconstruct the same root without a hash collision), but
    // cross-checking the signed `size` closes the gap explicitly rather than resting on collision-resistance alone.
    if bundle.inclusion.tree_size != checkpoint.size {
        return fail(CheckKind::MerkleInclusion, ErrorCode::MerkleProofInvalid);
    }
    pass_detail(
        CheckKind::MerkleInclusion,
        CheckDetail {
            tree_size: Some(bundle.inclusion.tree_size),
            ..CheckDetail::empty()
        },
    )
}

/// `Checkpoint` — signed by ≥ max(1, required_witnesses) trusted log keys; origin matches the policy if supplied.
/// Re-counts cosignatures independently (it does not depend on the structurally parsed `ctx.checkpoint`).
pub(crate) fn check_checkpoint(bundle: &ThoughtmarkBundle, policy: &Policy) -> CheckOutcome {
    match count_checkpoint_cosignatures(&bundle.checkpoint, &policy.trusted_log_keys) {
        Ok((checkpoint, count)) => {
            let required = u32::from(policy.required_witnesses);
            let detail = CheckDetail {
                matched: Some(count),
                required: Some(required),
                ..CheckDetail::empty()
            };
            if let Some(expected_origin) = &policy.log_origin
                && expected_origin != &checkpoint.origin
            {
                return fail_detail(
                    CheckKind::Checkpoint,
                    ErrorCode::CheckpointSignatureInvalid,
                    detail,
                );
            }
            let floor = required.max(1);
            if count >= floor {
                pass_detail(CheckKind::Checkpoint, detail)
            } else {
                fail_detail(
                    CheckKind::Checkpoint,
                    ErrorCode::CheckpointSignatureInvalid,
                    detail,
                )
            }
        }
        Err(e) => fail(CheckKind::Checkpoint, e.code()),
    }
}

/// `Consistency` — wired but inert at 1.0: the offline bundle carries no prior trusted root, so there is nothing
/// to reconcile `verify_consistency` against. The slot, the `CONSISTENCY_PROOF_INVALID` code, and the call path
/// are frozen; a Phase-4 witness/old-root source activates it. Always `Skipped`.
pub(crate) fn check_consistency(_bundle: &ThoughtmarkBundle) -> CheckOutcome {
    skipped(CheckKind::Consistency)
}

/// `AnchorReceipt` — skipped unless `require_anchor`; otherwise ≥1 anchor must prove a plausible time bound.
/// Returns the outcome plus the tightest UPPER bound (min over passing anchors), `None` at Phase 3.
pub(crate) fn check_anchor_receipt(
    bundle: &ThoughtmarkBundle,
    policy: &Policy,
    anchors: &dyn AnchorVerifier,
    now: UnixMillis,
) -> (CheckOutcome, Option<UnixMillis>) {
    if !policy.require_anchor {
        return (skipped(CheckKind::AnchorReceipt), None);
    }
    let params = VerifyParams {
        trusted_keys: &policy.trusted_log_keys,
    };
    let mut best: Option<i64> = None;
    let mut any_valid = false;
    let mut last_code = ErrorCode::AnchorReceiptMalformed;
    for receipt in &bundle.anchors {
        match anchors.verify_anchor(&bundle.checkpoint, receipt, &params) {
            AnchorVerdict::Valid {
                time_lower_bound, ..
            } => {
                let within = match now.0.checked_add(policy.max_clock_skew_ms) {
                    Some(ceiling) => time_lower_bound.0 <= ceiling,
                    None => false,
                };
                if within {
                    any_valid = true;
                    best = Some(match best {
                        Some(x) => x.min(time_lower_bound.0),
                        None => time_lower_bound.0,
                    });
                } else {
                    last_code = ErrorCode::AnchorTimeImplausible;
                }
            }
            AnchorVerdict::Pending => last_code = ErrorCode::AnchorReceiptMalformed,
            AnchorVerdict::Invalid(code) => last_code = code,
        }
    }
    if any_valid {
        (pass(CheckKind::AnchorReceipt), best.map(UnixMillis))
    } else {
        (fail(CheckKind::AnchorReceipt, last_code), None)
    }
}

/// `ContributionLineage` — walk the DAG and check the policy's required actions. Returns the outcome plus the
/// populated lineage steps (on pass).
pub(crate) fn check_contribution_lineage(
    bundle: &ThoughtmarkBundle,
    policy: &Policy,
    ctx: &Ctx,
) -> (CheckOutcome, Option<Vec<LineageStep>>) {
    let Some(statement) = &ctx.statement else {
        return (
            fail(
                CheckKind::ContributionLineage,
                ErrorCode::PredicateSchemaInvalid,
            ),
            None,
        );
    };
    let Ok(trail) = serde_json::from_value::<TrailView>(statement.predicate.clone()) else {
        return (
            fail(CheckKind::ContributionLineage, ErrorCode::LedgerBrokenLink),
            None,
        );
    };
    match lineage::walk(
        &trail,
        &bundle.turn_bodies,
        &bundle.run_manifests,
        policy.required_actions.as_deref(),
    ) {
        Ok(steps) => (pass(CheckKind::ContributionLineage), Some(steps)),
        Err(e) => (fail(CheckKind::ContributionLineage, e.code()), None),
    }
}

#[cfg(test)]
mod tests {
    //! `parse_subject_name` edge cases (the `"trail:<id>@<tree_size>"` parser feeding the StatementBinding
    //! tree-size check) — the malformed forms a conformance vector cannot enumerate cheaply. Unwrap-free.
    use super::*;

    #[test]
    fn parse_subject_name_accepts_canonical_decimal() {
        assert_eq!(parse_subject_name("trail:demo@5"), Some(5));
        assert_eq!(parse_subject_name("trail:demo@0"), Some(0));
        // `rfind('@')` takes the LAST `@`, so an `@` inside the id is tolerated.
        assert_eq!(parse_subject_name("trail:a@b@7"), Some(7));
    }

    #[test]
    fn parse_subject_name_rejects_malformed() {
        assert_eq!(parse_subject_name("nope"), None); // no `trail:` prefix
        assert_eq!(parse_subject_name("trail:demo"), None); // no `@`
        assert_eq!(parse_subject_name("trail:demo@"), None); // empty size
        assert_eq!(parse_subject_name("trail:demo@01"), None); // non-canonical leading zero
        assert_eq!(parse_subject_name("trail:demo@x"), None); // non-numeric
    }
}
