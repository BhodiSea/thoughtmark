<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase 1 — follow-ups requiring a human (protected guardrails)

The Phase-1 Tier-0 audit + hardening pass is complete; everything an agent is permitted to touch is done
(see the change set below). The items here remain because they live in **agent-forbidden** paths
(`.github/**`, `.claude/**`, `clippy.toml`, `CLAUDE.md`) per `.claude/settings.json`. Each is small and
spelled out so a maintainer can apply it directly.

Three of these are the **exit-gate CI additions** already specified verbatim in
[`docs/ci-handoff-phase-1.md`](ci-handoff-phase-1.md) — they are listed there with ready-to-paste YAML and SHA
pins. This doc adds the two governance/teeth items that surfaced in the audit.

## What the agent already did (no action needed)

- **Armed the UTF-16 sort guard.** Added `spec/vectors/canon/0004` (`{"￿":1,"😀":2}` → `{"😀":2,"￿":1}`) — the
  first vector that discriminates UTF-16 from code-point/UTF-8 order. Verified by deliberately regressing the
  sort to code-point order and watching `canon/0004` fail across the native + pure-TS executors, then reverting.
  The prior `😀`-vs-`z` case could not catch this. Corpus bumped to `0.1.1` (additive; no expected byte changed).
- Added the two missing required proptests (`validate_no_float` rejection classes; `hash(canonicalize(x))`
  stability), edge-case tests (rare C0 / DEL-raw escaping, integer boundaries, `-0.0`), tightened `UnixMillis`
  deserialize to reject non-canonical decimals, completed the `thoughtmark-schema` no-panic clippy wall, extended
  the `cid` fuzz target to also fuzz the parser (`cid_from_str`) + a round-trip invariant, added `domain/0002`
  (object) + `domain/0003` (manifest) vectors and taught the pure-TS oracle all three domains.
- Synced editable docs (roadmap phase-1 / 00-overview / phase-6, research architecture §4.2 / quality-foundations)
  to ADR-0001's in-house amendment.
- All local gates green: `cargo nextest` (41), `clippy -D warnings`, `cargo fmt --check`, `tm bless --check` (15),
  dep-direction + no-getrandom guards, and cross-language conformance (native Rust + WASM/Node + pure-TS oracle).

---

## 1–3. Exit-gate CI additions — see `docs/ci-handoff-phase-1.md`

These reach the roadmap's *full* exit gate; the four-executor byte-parity already runs for the three
non-browser executors. Configs are in the handoff doc:

| # | Item | Where |
|---|------|-------|
| 1 | 3-browser Playwright conformance matrix (Chromium/Firefox/WebKit) | handoff §1 (`.github/workflows/ci.yml`) |
| 2 | `cargo hack --feature-powerset` (feature-combo safety net) | handoff §2 (`.github/workflows/ci.yml`) |
| 3 | `jcs`/`cid` fuzz native↔wasmtime differential leg | handoff §3 (`.github/workflows/nightly-fuzz.yml` + a new `scripts/fuzz-differential.sh`, which an agent **can** author) |

> Note on §1: `packages/core` `test:wasm` (`package.json:28`) is currently a **no-op stub** that prints a string.
> When adopting the browser job, replace it with a real `test:browser` script + `@vitest/browser`/`playwright`
> devDeps (both in `packages/**`, agent-editable) so the YAML only needs to invoke it.

## 4. Give the nightly fuzz job teeth — remove `|| true`

`.github/workflows/nightly-fuzz.yml:24-29` swallows every fuzz failure, so a discovered crash/panic still reports
green. Drop `|| true` and fail fast:

```yaml
      - name: Smoke fuzz targets briefly
        working-directory: fuzz
        run: |
          set -euo pipefail
          for t in jcs cid; do
            cargo +nightly fuzz run "$t" -- -runs=20000 -max_total_time=120
          done
```

## 5. Protected-doc drift — sync to ADR-0001 as amended

The in-house-JCS amendment is authoritatively recorded in `docs/adr/0001-jcs-crate.md` and the
agent-editable docs are synced. These two protected files still mandate the old approach.

### `CLAUDE.md` — invariant **I2**

```diff
-- **I2 JCS-before-hash.** ALWAYS canonicalize JSON via RFC 8785 JCS (`serde_json_canonicalizer`) before hashing —
-  no bare `H(json)`. `serde_jcs` is **BANNED** (abandoned, RFC 8785 divergences — ADR-0001).
++ **I2 JCS-before-hash.** ALWAYS canonicalize JSON via RFC 8785 JCS before hashing — no bare `H(json)` — through
+  the single in-house choke point `thoughtmark_core::canon::jcs` (ADR-0001 **amended**: `serde_json_canonicalizer`
+  is `std`-only, so it is a dev-only differential oracle, not the implementation). `serde_jcs` is **BANNED**
+  (abandoned, RFC 8785 divergences — ADR-0001).
```

### `CLAUDE.md` — "Never do" list

```diff
-- Use bare Ed25519 `verify` (use `verify_strict`); re-implement JCS; use `serde_jcs`.
+- Use bare Ed25519 `verify` (use `verify_strict`); add a SECOND canonicalizer (the in-house `canon::jcs` is the
+  one choke point — ADR-0001 amended); use `serde_jcs`.
```

### `.claude/rules/crypto-invariants.md` — first bullet

```diff
-- Canonicalize via `serde_json_canonicalizer` (RFC 8785) before any hash. Never re-implement JCS. `serde_jcs` is
-  BANNED (ADR-0001).
+- Canonicalize via the single in-house RFC 8785 choke point `thoughtmark_core::canon::jcs` before any hash
+  (ADR-0001 amended: `serde_json_canonicalizer` is `std`-only → dev-only differential oracle, not the impl).
+  `serde_jcs` is BANNED (ADR-0001).
```

## 6. (Optional) historical doc references

These are **accurate as historical record** (Phase 0 *did* pin the crate, before the Phase-1 amendment), so they
need no change — listed only for completeness:
`docs/roadmap/phase-0-foundations.md:23,80,112`, `docs/research/quality-foundations.md:807,860`. To re-sweep:
`grep -rn "serde_json_canonicalizer" docs/ CLAUDE.md .claude/`.
