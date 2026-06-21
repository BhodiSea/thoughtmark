// SPDX-License-Identifier: Apache-2.0
//! The §5.12 schema determinism-contract invariants as properties: `canonicalize` is idempotent on a `Turn`;
//! `turn_id` is a pure function equal to `hash_domain(BLAKE3, TURN, canon(t))`; any turn-byte mutation changes
//! `trail_root`; `export_prov` is a pure function of its inputs. These need both the schema wire types and core's
//! hashing, so they live as a core integration test (schema is a core dev-dependency). Integration tests opt out
//! of the no-panic wall — a panic IS the failure signal.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use proptest::prelude::*;
use std::collections::BTreeMap;
use thoughtmark_core::{Digest, HashAlg, UnixMillis, canon, canonicalize};
use thoughtmark_schema::{
    Action, CanonVersion, ContentDigest, ContentPart, ContributionLedger, LedgerEntry,
    ParticipantRef, SchemaVersion, Trail, Turn, TurnId, TurnRole, export_prov, trail_root, turn_id,
};

fn arb_digest() -> impl Strategy<Value = Digest> {
    proptest::array::uniform32(any::<u8>()).prop_map(|bytes| Digest {
        alg: HashAlg::Blake3,
        bytes,
    })
}

prop_compose! {
    /// A valid `Turn` with an in-range `sequence` (so it always canonicalizes), a single hashed content part,
    /// 0–2 parents, and 1–3 ledger entries.
    fn arb_turn()(
        sequence in 0u64..=9_007_199_254_740_991,
        body in arb_digest(),
        parents in proptest::collection::vec(arb_digest(), 0..3),
        n_entries in 1usize..=3,
    ) -> Turn {
        let entries: Vec<LedgerEntry> = (0..n_entries)
            .map(|i| LedgerEntry {
                action: Action::Create,
                attributed_to: ParticipantRef { id: "did:key:zProptest".to_string() },
                attested_at: UnixMillis(1_700_000_000_000 + i64::try_from(i).unwrap_or(0)),
                approval_scope: None,
                note_digest: None,
            })
            .collect();
        Turn {
            schema_version: SchemaVersion::V1,
            canon_version: CanonVersion::TmJcs1,
            sequence,
            role: TurnRole::Ai,
            content: vec![ContentPart::Content {
                media_type: "text/plain".to_string(),
                body: ContentDigest::Hashed { alg: HashAlg::Blake3, digest_hex: body.to_hex() },
            }],
            parents: parents.into_iter().map(TurnId).collect(),
            supersedes: None,
            ledger: ContributionLedger { entries },
            run_manifest_ref: None,
            extensions: BTreeMap::new(),
        }
    }
}

fn trail_with(turns: Vec<TurnId>, head: TurnId) -> Trail {
    Trail {
        schema_version: SchemaVersion::V1,
        canon_version: CanonVersion::TmJcs1,
        trail_id: "proptest".to_string(),
        created_attested_at: UnixMillis(1_700_000_000_000),
        turns,
        head,
        extensions: BTreeMap::new(),
    }
}

proptest! {
    /// `canonicalize` is idempotent: canonicalizing already-canonical bytes is a no-op.
    #[test]
    fn canonicalize_is_idempotent(turn in arb_turn()) {
        let once = canonicalize(&turn).unwrap();
        let s = core::str::from_utf8(&once).unwrap();
        prop_assert_eq!(canon::canonicalize_str(s).unwrap(), once);
    }

    /// `turn_id` is a pure function equal to `hash_domain(BLAKE3, TURN, canonicalize(turn))`.
    #[test]
    fn turn_id_is_pure_and_domain_separated(turn in arb_turn()) {
        let a = turn_id(&turn).unwrap();
        let b = turn_id(&turn.clone()).unwrap();
        prop_assert_eq!(a, b);
        let manual = canon::hash_domain(HashAlg::Blake3, canon::domain::TURN, &canonicalize(&turn).unwrap());
        prop_assert_eq!(a.0, manual);
    }

    /// `turn_id` is stable under a JCS key re-sort: the SAME logical turn serialized with non-canonical object
    /// key order yields the IDENTICAL `turn_id` once it passes through the JCS choke point. `serde_json` emits
    /// struct fields in declaration order (`schema_version` first), which is NOT the alphabetical JCS order
    /// (`canon_version` first) — so this is a genuine top-level key reordering for every generated turn, pinning
    /// the §5.12 re-sort invariance at the schema level (not only at core's JCS layer).
    // `serde_json::to_string` is the I2 `disallowed-methods` ban (no hashing outside the canon choke point); here
    // it is the deliberate *source of non-canonical bytes*, which are then re-canonicalized via `canonicalize_str`
    // BEFORE hashing — so I2 holds. The scoped allow keeps the ban active for the rest of the file.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn turn_id_stable_under_key_reordering(turn in arb_turn()) {
        let id = turn_id(&turn).unwrap();
        let reordered = serde_json::to_string(&turn).unwrap();
        let recanon = canon::canonicalize_str(&reordered).unwrap();
        let id_from_reordered =
            TurnId(canon::hash_domain(HashAlg::Blake3, canon::domain::TURN, &recanon));
        prop_assert_eq!(id, id_from_reordered);
    }

    /// Any change to a referenced turn id changes `trail_root` (tamper-evidence).
    #[test]
    fn mutating_a_turn_id_changes_trail_root(a in arb_digest(), b in arb_digest()) {
        prop_assume!(a.bytes != b.bytes);
        let root_a = trail_root(&trail_with(vec![TurnId(a)], TurnId(a))).unwrap();
        let root_b = trail_root(&trail_with(vec![TurnId(b)], TurnId(b))).unwrap();
        prop_assert_ne!(root_a, root_b);
    }

    /// `export_prov` is a pure function of its inputs.
    #[test]
    fn export_prov_is_pure(turn in arb_turn()) {
        let trail = trail_with(vec![], TurnId(Digest { alg: HashAlg::Blake3, bytes: [0u8; 32] }));
        let turns = vec![turn];
        let a = export_prov(&trail, &turns, &[]);
        let b = export_prov(&trail, &turns, &[]);
        prop_assert_eq!(a, b);
    }
}
