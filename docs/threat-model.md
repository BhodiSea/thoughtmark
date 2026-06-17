<!-- SPDX-License-Identifier: Apache-2.0 -->
# Threat model — what thoughtmark proves, and what it does not

This is a first-class artifact, not a footnote. The system proves **integrity-of-record**, never
**validity-of-record** or **faithfulness** (I7). Keep this distinction explicit in docs and UI: **green CI, a valid
signature, or a verified proof is never a claim about the content being notarized.**

## Proves / does NOT prove

| The system PROVES (integrity-of-record) | The system does NOT prove |
|---|---|
| A record **existed at a time T**, in a given lineage L, **unaltered since capture** (byte-identity to a committed digest). | **Validity** — that the recorded content is true, correct, or non-harmful. |
| **Append-only consistency** — the log can be extended but not rewritten (RFC 6962 consistency proofs). | **Faithfulness** — that a logged reasoning trail reflects the computation that actually produced an output. |
| **Signer identity** — a signature verifies under a specific public key; the message is authentic to that key (Ed25519 `verify_strict`). | **Split-view resistance** without external gossip/witnesses — two parties may be shown divergent but internally-consistent lineages. |
| The capture's **internal structure** (turns, contributions, anchors) is well-formed and self-consistent. | **Truth-at-capture / the oracle problem** — who captured the record, and why their initial claim should be trusted. |

## Out of scope / explicitly not claimed

- We do not attest that an AI model "really thought" the logged reasoning (no faithfulness claim).
- We do not prevent a malicious capturer from logging a false-but-well-formed record; we make it **tamper-evident
  after capture**, not true at capture.
- We do not provide global consensus; without witnesses, split-view is a residual risk addressed by the
  consistency monitor (Phase 4) and external anchoring (Tier 2).

## Why this matters for an AI-authored codebase

The primary author is Claude Code. The honesty frame is load-bearing on the **type names, field names, and verb
choices** (`NotEstablished`, `attested_at`, `attributed_to`, `model_self_reported_version`), so the API itself
resists overclaiming. Any change that could let a green check be read as a validity/faithfulness claim is a
threat-model regression and must be rejected.
