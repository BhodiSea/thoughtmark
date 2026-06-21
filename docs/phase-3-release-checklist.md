<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase 3 — API FREEZE → 1.0 release checklist (human-required steps)

The code half of Phase 3 (the `verify()` pipeline, the frozen-surface types, the `verify` op + vectors, the typed
`@thoughtmark/core` mirror, and the freeze-gate *artifacts*) is implemented and green under the local gates. The
steps below are the ones the AI author **cannot** do — they touch deny-listed paths (`.github/**`, `deny.toml`,
`rust-toolchain.toml`, `CODEOWNERS`), external registry/OIDC/ruleset settings, or the irreversible publish itself.
Do them in order; do not tag `v1.0.0` until every gate is green.

> Authority boundary: the AI author's allow/deny list (`.claude/settings.json`) forbids editing `.github/**`,
> `deny.toml`, `rust-toolchain.toml`, `clippy.toml`, `CODEOWNERS`; `cargo publish` / `npm publish` / `git push`
> are **ask**-gated (never silent). Everything below lives on the human side of that line.

## 0. Re-pin the reproducible `.wasm` (REQUIRED — the verify op changed the binary)

Adding the `verify` op changed `thoughtmark_wasm_bg.wasm`, so the committed `spec/vectors/wasm.blake3` is stale.
`scripts/assert-wasm-blake3.sh` enforces the hash **only in CI** (or with `THOUGHTMARK_ENFORCE_WASM_HASH=1`), so
local `just ci` stays green — but CI will fail until the pin is regenerated **in the pinned Linux container**
(wasm-bindgen output is byte-stable only within a fixed OS/libc; see memory `wasm-blake3-pin-must-be-ci-generated`).

- In CI (or the pinned container): `just ci-wasm` prints the freshly-built BLAKE3; commit that value to
  `spec/vectors/wasm.blake3`. Do **not** pin a laptop-built hash.

## 1. Activate the CI gate jobs — `.github/workflows/ci.yml` (deny-listed; human edits)

Each new local gate already has a `just` recipe + script; wire the blocking job that invokes it:

| New job/step | Invokes (already in-repo) | Notes |
|---|---|---|
| `semver` | `just ci-api` → `cargo public-api -p thoughtmark-core diff` + `cargo semver-checks` | `cargo-public-api` needs a **nightly** rustdoc-json; install nightly only for this job. Seed the baseline once (§4). `cargo-semver-checks` is inert until 1.0 is published, then blocks 1.0.x breaks. |
| `api-extractor` + `changesets` | `pnpm --filter @thoughtmark/core api:check` + `pnpm changeset status --since=origin/main` | needs the devDeps + baseline from §4. Add to the existing `ts-wasm` job. |
| `release-train-consistency` | `./scripts/release-train-consistency.sh origin/main` | needs `fetch-depth: 0` (it diffs against `origin/main`). |
| `manifest-toolchain` | `./scripts/assert-manifest-toolchain.sh` | already runs in `ci-docs`; CI sets `CI=true` so it enforces. |
| `mutants` (own job, or nightly) | `cargo mutants --in-place` (config `.cargo/mutants.toml`, scoped to `verify/**`) | slow; keep out of the required PR set or run nightly. |

Then add each new required job name to the branch ruleset (§5).

## 2. Activate publishing — `.github/workflows/release.yml` (deny-listed; human edits)

`release.yml` is already wired (triggers on `v*` + dispatch, sets `SOURCE_DATE_EPOCH`, emits a CycloneDX SBOM,
attests `target/release/tm`). Extend it:

- **`publish-crates`** job — `permissions: { id-token: write }`; publish in dependency order
  `thoughtmark-vectors` → `thoughtmark-schema` → `thoughtmark-core` via **crates.io Trusted Publishing (OIDC)** —
  no `CARGO_REGISTRY_TOKEN`.
- **`publish-npm`** job — `permissions: { id-token: write }`; build the wasm + `pnpm --filter @thoughtmark/core
  build`, then `npm publish --provenance --access public` for `@thoughtmark/vectors` and `@thoughtmark/core`
  (npm Trusted Publishing — no `NPM_TOKEN`).
- **SBOM emit-and-attach** — keep `cargo cyclonedx`; add `pnpm --filter @thoughtmark/core sbom` (after the devDep
  in §4) and attach both SBOMs as release assets; extend `actions/attest-build-provenance` to the `.crate`(s),
  the `.wasm`, and the npm tarballs (not just `tm`).
- **`consumer-verify`** job — after publish, dogfo the mission: `npm audit signatures` and `cosign verify-attestation`
  against the published artifacts.

## 3. Configure OIDC Trusted Publishing (registry settings — no repo file)

- **crates.io** → each crate (`thoughtmark-core`, `thoughtmark-schema`, `thoughtmark-vectors`) → Settings →
  Trusted Publishing → add a GitHub Actions publisher (repo `OWNER/thoughtmark`, workflow `release.yml`, optional
  environment `release`). **Ordering risk:** a brand-new crate name may need a one-time token-based `cargo publish`
  to reserve it, then switch to OIDC for `1.0.1+`. `thoughtmark-vectors` has never been published — reserve it.
- **npm** → org `@thoughtmark` → each package → Settings → Trusted Publisher → GitHub Actions, repo + `release.yml`.
  The packages must be `private:false` (set in §6).

## 4. Seed the API-freeze baselines + devDeps (lockfile-changing; human)

- **devDeps** (updates `pnpm-lock.yaml` / `Cargo` tools):
  - `pnpm add -D -w @changesets/cli` and `pnpm --filter @thoughtmark/core add -D @microsoft/api-extractor
    @cyclonedx/cyclonedx-npm`.
  - Add `@thoughtmark/core` scripts: `"api:check": "api-extractor run"`, `"api:update": "api-extractor run
    --local"`, `"sbom": "cyclonedx-npm --output-format JSON --output-file sbom.cdx.json"`.
  - `cargo install cargo-public-api cargo-semver-checks cargo-mutants --locked` (CI + maintainer).
- **Baselines (commit once, then they gate):**
  - `cargo public-api -p thoughtmark-core --rustdoc-json <nightly> > crates/thoughtmark-core/public-api.txt`
    (review — this captures the frozen §14 surface exactly).
  - `pnpm --filter @thoughtmark/core build && pnpm --filter @thoughtmark/core api:update` →
    `packages/core/etc/thoughtmark-core.api.md` (config is already at `packages/core/api-extractor.json`).

## 5. Repository rulesets (GitHub Settings → Rules, or committed `.github/` ruleset JSON; human)

- **`main`**: require status checks `rust`, `conformance`, `ts-wasm`, `docs-licensing`, `actions-hardening`
  **plus** the new `semver` / `api-extractor` / `release-train-consistency` / `manifest-toolchain` jobs; require
  signed commits; linear history; ≥1 review; block force-push + deletion.
- **`v*` tags**: a separate ruleset making release tags **immutable** (block updates + deletions).

## 6. Version bumps + the publish event (the freeze cut; human)

- Bump the workspace crate version `0.1.0 → 1.0.0` (`Cargo.toml [workspace.package] version`), drop `private:true`
  and set `version: 1.0.0` on `@thoughtmark/core` + `@thoughtmark/vectors`.
- Bump the **corpus** freeze cut `spec/vectors/VERSION 0.8.0 → 1.0.0` (a deliberate MAJOR signalling "frozen"; it
  mutates **no** expected byte, so `release-train-consistency.sh` does not fire — add a CHANGELOG entry stating the
  freeze-cut intent so a reviewer isn't surprised).
- Finish the `@thoughtmark/vectors` package (currently a stub `packages/vectors/package.json`): add `exports` /
  `files` shipping the corpus JSON (and a `tsconfig.build.json` + `build` mirroring `@thoughtmark/core` if you ship
  a TS index). Finish the `thoughtmark-vectors` **crate** vendoring (a `build.rs` that copies `spec/vectors/**`
  into `OUT_DIR`, or a pre-publish vendor step) so the published `.crate` is self-contained.
- Merge, then `git tag v1.0.0 && git push origin v1.0.0` → `release.yml` runs the OIDC publish of the trio.
  **Irreversible** — crates.io/npm do not allow re-publishing a version. Verify every gate green first.

## 7. OpenSSF Best Practices Badge (human)

Register the repo at <https://www.bestpractices.dev>, answer the questionnaire, and embed the badge in `README.md`
(the README edit itself is AI-allowed). OpenSSF Scorecard already runs (`.github/workflows/scorecard.yml`).

---

## Known coverage boundaries (not blockers — recorded for the reviewer)

- **Executor D (the independent pure-TS oracle) skips the `verify` op.** Reimplementing the whole §11 orchestrator
  byte-identically in TS would be a second full pipeline; verify byte-parity is gated by executor A (native Rust)
  and executor B (WASM under Node), which both reproduce every `verify/*` vector. See the skip comment in
  `packages/core/test/oracle.conformance.test.ts`.
- **`Consistency` and `AnchorReceipt` are wired-but-inert at 1.0.** No `AnchorVerifier` impl ships before Phase 4
  (`thoughtmark-anchor`), and the offline bundle carries no prior trusted root for a consistency reconciliation —
  the check slots, codes, and call paths are frozen; the *capability* arrives in Phase 4.
- **Frozen-surface decisions taken** (permanent at 1.0): `Policy` (runtime, key-bearing) vs `PolicyWire` (op
  input, key strings); `NotEstablished` is a constant-emitting unit struct; `required_witnesses == 0` means "no
  witnesses beyond the mandatory single log signer"; `IdentityResolver` is a sync trait; lineage `participant_kind`
  is derived from turn role (a ledger entry carries only the attributed DID). The TS `VerificationResult` mirrors
  §14.6 camelCase/bigint via a mapping over the snake_case JCS wire (the byte-identity source of truth).
- **Future-phase verbs** (`sign`, `verifyEnvelope`, `redact`, `export_`, `verifyAnchor`, `anchor`) ship as typed
  signatures in `@thoughtmark/core` that throw until their backends land (additive MINOR per §14.7), so the §14.6
  type surface is complete at 1.0.
