// SPDX-License-Identifier: Apache-2.0
//! The contribution-lineage DAG walk (arch §11.2, the `ContributionLineage` check).
//!
//! Replays the stapled `Turn` bodies the predicate `Trail` references: recompute each `turn_id`, then assert the
//! DAG is well-formed — no cycle, no dangling parent, every `supersedes` target present, `attested_at`
//! non-decreasing along the chain, every `run_manifest_ref` matched by a stapled manifest, and the policy's
//! `required_actions` all present. All iteration is over `Vec`/`BTreeMap`/`BTreeSet` (never a `HashMap`) and
//! cycle detection is Kahn's algorithm over `Vec` in-degree counts (no recursion — the WASM stack), so the result
//! is byte-deterministic. Returns the populated [`LineageStep`]s on success.

use crate::canon::domain::{MANIFEST, TURN};
use crate::canon::{Digest, HashAlg, hash_domain};
use crate::error::{Error, ErrorCode};
use crate::scalar::{Action, ParticipantKind};
use crate::verify::result::LineageStep;
use crate::verify::statement::{TrailView, TurnView};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

fn broken() -> Error {
    Error::Lineage(ErrorCode::LedgerBrokenLink)
}
fn non_monotonic() -> Error {
    Error::Lineage(ErrorCode::LedgerNonMonotonicTime)
}
fn unsatisfied() -> Error {
    Error::Lineage(ErrorCode::PolicyUnsatisfied)
}

/// A stable map/set key for a [`Digest`]: `alg ":" hex`.
fn digest_key(d: &Digest) -> String {
    let mut s = String::from(d.alg.as_str());
    s.push(':');
    s.push_str(&d.to_hex());
    s
}

/// One parsed, verified turn in the lineage.
struct ParsedTurn {
    view: TurnView,
    /// The newest `attested_at` among the turn's ledger entries (the turn's representative time).
    turn_time: i64,
}

/// Walk the lineage DAG and return its steps, or the first failure.
///
/// # Errors
/// `LedgerBrokenLink` / `LedgerNonMonotonicTime` / `PolicyUnsatisfied` (carried in [`Error::Lineage`]) for a
/// structural / temporal / policy failure; `Error::Internal` for an impossible index.
pub(crate) fn walk(
    trail: &TrailView,
    turn_bodies: &[Vec<u8>],
    run_manifests: &[Vec<u8>],
    required_actions: Option<&[Action]>,
) -> Result<Vec<LineageStep>, Error> {
    let (parsed, index) = parse_and_index(trail, turn_bodies)?;
    assert_acyclic(&parsed, &index)?;
    check_manifests_and_actions(&parsed, run_manifests, required_actions)?;
    build_steps(trail, &parsed, &index)
}

/// The turn's representative time = its newest ledger `attested_at`, asserting the entries are non-decreasing.
fn entries_time(view: &TurnView) -> Result<i64, Error> {
    let mut turn_time = i64::MIN;
    for entry in &view.ledger.entries {
        if entry.attested_at.0 < turn_time {
            return Err(non_monotonic());
        }
        turn_time = entry.attested_at.0;
    }
    Ok(turn_time)
}

/// Parse + identify every stapled body; assert each is trail-referenced, unique, non-empty, and that the trail's
/// declared turns are all present (a complete lineage).
fn parse_and_index(
    trail: &TrailView,
    turn_bodies: &[Vec<u8>],
) -> Result<(Vec<ParsedTurn>, BTreeMap<String, usize>), Error> {
    if trail.turns.is_empty() {
        return Err(broken());
    }
    let mut trail_ids: BTreeSet<String> = BTreeSet::new();
    for tid in &trail.turns {
        if !trail_ids.insert(digest_key(tid)) {
            return Err(broken()); // a duplicate turn id in the trail
        }
    }
    if !trail_ids.contains(&digest_key(&trail.head)) {
        return Err(broken()); // the head is not a declared turn
    }

    let mut parsed: Vec<ParsedTurn> = Vec::with_capacity(turn_bodies.len());
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    for body in turn_bodies {
        let view: TurnView = serde_json::from_slice(body).map_err(|_| broken())?;
        let key = digest_key(&hash_domain(HashAlg::Blake3, TURN, body));
        if !trail_ids.contains(&key) {
            return Err(broken()); // a stapled body the trail does not reference
        }
        if view.ledger.entries.is_empty() {
            return Err(broken()); // a turn must carry ≥1 ledger entry
        }
        let turn_time = entries_time(&view)?;
        if index.insert(key, parsed.len()).is_some() {
            return Err(broken()); // two bodies with the same turn id
        }
        parsed.push(ParsedTurn { view, turn_time });
    }
    for tid in &trail.turns {
        if !index.contains_key(&digest_key(tid)) {
            return Err(broken()); // a declared turn with no stapled body
        }
    }
    Ok((parsed, index))
}

/// Build the parent→child edges (asserting parents/supersedes targets exist and time is monotonic), then prove
/// the graph is acyclic via Kahn's algorithm.
fn assert_acyclic(parsed: &[ParsedTurn], index: &BTreeMap<String, usize>) -> Result<(), Error> {
    let n = parsed.len();
    let mut children: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut in_degree: Vec<u32> = Vec::with_capacity(n);
    for _ in 0..n {
        children.push(Vec::new());
        in_degree.push(0);
    }

    for (i, turn) in parsed.iter().enumerate() {
        for parent in &turn.view.parents {
            let pidx = *index.get(&digest_key(parent)).ok_or_else(broken)?;
            children
                .get_mut(pidx)
                .ok_or(Error::internal("lineage.children"))?
                .push(i);
            let deg = in_degree
                .get_mut(i)
                .ok_or(Error::internal("lineage.indeg"))?;
            *deg = deg
                .checked_add(1)
                .ok_or(Error::internal("lineage.indeg.add"))?;
            let parent_time = parsed
                .get(pidx)
                .ok_or(Error::internal("lineage.parent"))?
                .turn_time;
            if turn.turn_time < parent_time {
                return Err(non_monotonic()); // a child cannot predate its parent
            }
        }
        if let Some(superseded) = &turn.view.supersedes
            && !index.contains_key(&digest_key(superseded))
        {
            return Err(broken()); // a dangling supersedes target
        }
    }

    // Kahn's algorithm: a DAG topologically sorts iff every node is removed.
    let mut queue: Vec<usize> = Vec::new();
    for (i, deg) in in_degree.iter().enumerate() {
        if *deg == 0 {
            queue.push(i);
        }
    }
    let mut processed = 0usize;
    while let Some(i) = queue.pop() {
        processed = processed
            .checked_add(1)
            .ok_or(Error::internal("lineage.processed"))?;
        let child_list = children
            .get(i)
            .ok_or(Error::internal("lineage.kahn.children"))?;
        for &c in child_list {
            let deg = in_degree
                .get_mut(c)
                .ok_or(Error::internal("lineage.kahn.indeg"))?;
            *deg = deg
                .checked_sub(1)
                .ok_or(Error::internal("lineage.kahn.sub"))?;
            if *deg == 0 {
                queue.push(c);
            }
        }
    }
    if processed != n {
        return Err(broken()); // a cycle in the parents DAG
    }
    Ok(())
}

/// Match every `run_manifest_ref` to a stapled manifest, and assert the policy's required actions all appear.
fn check_manifests_and_actions(
    parsed: &[ParsedTurn],
    run_manifests: &[Vec<u8>],
    required_actions: Option<&[Action]>,
) -> Result<(), Error> {
    let mut manifest_ids: BTreeSet<String> = BTreeSet::new();
    for body in run_manifests {
        manifest_ids.insert(digest_key(&hash_domain(HashAlg::Blake3, MANIFEST, body)));
    }
    for turn in parsed {
        if let Some(reference) = &turn.view.run_manifest_ref
            && !manifest_ids.contains(&digest_key(reference))
        {
            return Err(broken());
        }
    }

    if let Some(required) = required_actions {
        let mut present: Vec<Action> = Vec::new();
        for turn in parsed {
            for entry in &turn.view.ledger.entries {
                if !present.contains(&entry.action) {
                    present.push(entry.action);
                }
            }
        }
        for action in required {
            if !present.contains(action) {
                return Err(unsatisfied());
            }
        }
    }
    Ok(())
}

/// Build the lineage steps in the trail's canonical turn order, then entry order.
fn build_steps(
    trail: &TrailView,
    parsed: &[ParsedTurn],
    index: &BTreeMap<String, usize>,
) -> Result<Vec<LineageStep>, Error> {
    let mut steps: Vec<LineageStep> = Vec::new();
    for tid in &trail.turns {
        let idx = *index
            .get(&digest_key(tid))
            .ok_or(Error::internal("lineage.step.index"))?;
        let turn = parsed
            .get(idx)
            .ok_or(Error::internal("lineage.step.turn"))?;
        let kind = role_to_kind(&turn.view.role);
        for entry in &turn.view.ledger.entries {
            steps.push(LineageStep {
                participant_kind: kind,
                participant_id: entry.attributed_to.id.clone(),
                action: entry.action,
                at: entry.attested_at,
            });
        }
    }
    Ok(steps)
}

/// Map a turn `role` token to a [`ParticipantKind`]. `"human"` is the only human kind; `"ai"`/`"system"`/`"tool"`
/// (and any other automated role) map to `Ai`, since v1 keys human-vs-AI at turn-role granularity (a ledger entry
/// carries only the attributed DID, not its own kind).
fn role_to_kind(role: &str) -> ParticipantKind {
    if role == "human" {
        ParticipantKind::Human
    } else {
        ParticipantKind::Ai
    }
}

#[cfg(test)]
mod tests {
    //! Mutation killers the conformance vectors cannot reach cheaply: the DAG failure modes a content-addressed
    //! corpus cannot mint (a cycle is infeasible to forge with valid `turn_id`s; non-monotonic/dangling need a
    //! re-signing cascade), tested directly against `assert_acyclic`/`walk`. Unwrap-free per the no-panic wall.
    use super::*;

    // A minimal well-formed Turn body (one `create` ledger entry, no parents/manifest). `walk` hashes the EXACT
    // bytes for the `turn_id`, so the body need not be JCS-canonical — only self-consistent.
    const BODY_A: &[u8] = br#"{"ledger":{"entries":[{"action":"create","attested_at":"1000","attributed_to":{"id":"did:a"}}]},"role":"ai"}"#;
    const BODY_B: &[u8] = br#"{"ledger":{"entries":[{"action":"approve","attested_at":"2000","attributed_to":{"id":"did:b"}}]},"role":"human"}"#;

    fn id_of(body: &[u8]) -> Digest {
        hash_domain(HashAlg::Blake3, TURN, body)
    }

    fn parsed_turn(parents: Vec<Digest>, time: i64) -> ParsedTurn {
        ParsedTurn {
            view: TurnView {
                role: String::from("ai"),
                parents,
                supersedes: None,
                ledger: crate::verify::statement::LedgerView {
                    entries: Vec::new(),
                },
                run_manifest_ref: None,
            },
            turn_time: time,
        }
    }

    #[test]
    fn single_well_formed_turn_walks() {
        let id = id_of(BODY_A);
        let trail = TrailView {
            turns: alloc::vec![id],
            head: id,
        };
        let bodies = alloc::vec![BODY_A.to_vec()];
        assert!(matches!(walk(&trail, &bodies, &[], None), Ok(s) if s.len() == 1));
    }

    #[test]
    fn declared_turn_without_body_is_broken() {
        let (ida, idb) = (id_of(BODY_A), id_of(BODY_B));
        let trail = TrailView {
            turns: alloc::vec![ida, idb],
            head: ida,
        };
        let bodies = alloc::vec![BODY_A.to_vec()]; // idb declared but not stapled
        assert!(
            matches!(walk(&trail, &bodies, &[], None), Err(e) if e.code() == ErrorCode::LedgerBrokenLink)
        );
    }

    #[test]
    fn duplicate_stapled_body_is_broken() {
        let ida = id_of(BODY_A);
        let trail = TrailView {
            turns: alloc::vec![ida],
            head: ida,
        };
        let bodies = alloc::vec![BODY_A.to_vec(), BODY_A.to_vec()];
        assert!(
            matches!(walk(&trail, &bodies, &[], None), Err(e) if e.code() == ErrorCode::LedgerBrokenLink)
        );
    }

    #[test]
    fn required_action_absent_is_unsatisfied() {
        let ida = id_of(BODY_A);
        let trail = TrailView {
            turns: alloc::vec![ida],
            head: ida,
        };
        let bodies = alloc::vec![BODY_A.to_vec()];
        let required = [Action::Reject]; // BODY_A only carries `create`
        assert!(
            matches!(walk(&trail, &bodies, &[], Some(&required)), Err(e) if e.code() == ErrorCode::PolicyUnsatisfied)
        );
    }

    #[test]
    fn linear_chain_is_acyclic() {
        let (id0, id1) = (id_of(b"node0"), id_of(b"node1"));
        let mut index = BTreeMap::new();
        index.insert(digest_key(&id0), 0usize);
        index.insert(digest_key(&id1), 1usize);
        let parsed = alloc::vec![
            parsed_turn(Vec::new(), 0),
            parsed_turn(alloc::vec![id0], 10)
        ];
        assert!(assert_acyclic(&parsed, &index).is_ok());
    }

    #[test]
    fn cycle_is_rejected() {
        let (id0, id1) = (id_of(b"node0"), id_of(b"node1"));
        let mut index = BTreeMap::new();
        index.insert(digest_key(&id0), 0usize);
        index.insert(digest_key(&id1), 1usize);
        // node0 → node1 and node1 → node0 (both times equal, so monotonicity passes and Kahn detects the cycle).
        let parsed = alloc::vec![
            parsed_turn(alloc::vec![id1], 0),
            parsed_turn(alloc::vec![id0], 0)
        ];
        assert!(
            matches!(assert_acyclic(&parsed, &index), Err(e) if e.code() == ErrorCode::LedgerBrokenLink)
        );
    }

    #[test]
    fn non_monotonic_time_is_rejected() {
        let (id0, id1) = (id_of(b"node0"), id_of(b"node1"));
        let mut index = BTreeMap::new();
        index.insert(digest_key(&id0), 0usize);
        index.insert(digest_key(&id1), 1usize);
        // node1 (time 50) is a child of node0 (time 100) — a child predating its parent.
        let parsed = alloc::vec![
            parsed_turn(Vec::new(), 100),
            parsed_turn(alloc::vec![id0], 50)
        ];
        assert!(
            matches!(assert_acyclic(&parsed, &index), Err(e) if e.code() == ErrorCode::LedgerNonMonotonicTime)
        );
    }

    #[test]
    fn dangling_parent_is_rejected() {
        let id0 = id_of(b"node0");
        let missing = id_of(b"not in the index");
        let mut index = BTreeMap::new();
        index.insert(digest_key(&id0), 0usize);
        let parsed = alloc::vec![parsed_turn(alloc::vec![missing], 0)];
        assert!(
            matches!(assert_acyclic(&parsed, &index), Err(e) if e.code() == ErrorCode::LedgerBrokenLink)
        );
    }
}
