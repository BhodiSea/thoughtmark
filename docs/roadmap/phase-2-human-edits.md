<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase 2 — human-only edits (to apply by hand)

Phase 2 (M0–M7) is landed on `phase-2-tier1-log-signing` and `just ci`-green: the full `Provenance/v1` schema, the
RFC 6962/9162 Merkle log, DSSE/Ed25519/did:key signing, the C2SP checkpoint, the `ThoughtmarkBundle` + anchor
seam, and the `thoughtmark-log` storage shell — **51 conformance vectors byte-identical across native Rust,
WASM/Node, and the independent pure-TS oracle**, with the four frozen format-identifier values pinned.

A handful of changes touch files an agent cannot edit (`.claude/**`, `.github/**`, `deny.toml`,
`rust-toolchain.toml` — deny-listed in `.claude/settings.json`). They activate CI gates the local code/scripts are
already prepared for. Apply these to take the wire-format **freeze candidate** to a fully-CI-enforced freeze. Each
item says **why**, the **exact change**, and **how to verify**.

> **One review flag (agent-editable, already applied — please confirm):** I set
> `clippy::multiple_crate_versions = "allow"` in the root `Cargo.toml` `[workspace.lints.clippy]`. Adding the
> audited `ed25519-dalek` stack introduced one unavoidable, benign transitive split — `cpufeatures` 0.2
> (sha2 / curve25519-dalek) vs 0.3 (blake3), unpinnable to a single major. `deny.toml` already classifies multiple
> versions as **warn**, and `cargo deny check` (in `ci-rust`) still reports it at that level — so the project's
> authoritative dependency monitor stays in force; I only stopped clippy from hard-failing on a split that
> contradicts the project's own `deny.toml = warn` policy. It is a dependency-hygiene nicety, NOT a
> correctness/security/no-panic gate. Revert if you disagree; then the alternative is downgrading blake3 to a
> cpufeatures-0.2 line.

---

## 1. `clippy.toml` — the bare-`verify` ban no longer resolves under ed25519-dalek 2.x

**Why.** `clippy.toml` bans `ed25519_dalek::VerifyingKey::verify` (SIG-1 / I6: force `verify_strict`). Now that
`ed25519-dalek` is a real dependency, clippy emits `warning: ed25519_dalek::VerifyingKey::verify does not refer to
a reachable function` — in dalek 2.x `verify` is a **trait** method (`signature::Verifier`), so the inherent-path
entry may not match it. The lint is not currently catching anything. (All core code uses `verify_strict`
exclusively, so there is no live violation — but the guardrail should actually fire.)

**Change (`clippy.toml`).** Replace the entry with the trait-qualified path (and silence the config warning):

```toml
# was:
{ path = "ed25519_dalek::VerifyingKey::verify", reason = "use verify_strict (rejects malleable sigs) — I6" },
# becomes (catch the Verifier trait method; allow-invalid silences the config warning if the path still can't resolve):
{ path = "ed25519_dalek::Verifier::verify", reason = "use verify_strict (rejects malleable sigs) — I6", allow-invalid = true },
```

**Verify the lint actually fires.** Temporarily add a bare `vk.0.verify(msg, &sig)` call in
`crates/thoughtmark-core/src/sign.rs::verify` and run
`cargo clippy -p thoughtmark-core -- -D warnings`; it MUST error with `disallowed_methods`. Revert the probe.
(Same applies to the inert `rand::thread_rng` / `rand::random` entries — add `allow-invalid = true` to silence
their config warnings; they are placeholders for crates not in the tree.)

---

## 2. `.github/workflows/ci.yml` — enforce the reproducible-`.wasm` BLAKE3 hash

**Why.** `scripts/assert-wasm-blake3.sh` (landed) fingerprints the built `.wasm` and, in CI, asserts it equals
`spec/vectors/wasm.blake3` — catching an un-reviewed `.wasm` change or toolchain drift (arch §12.5). wasm-bindgen
output is only byte-stable within a pinned environment, so the **canonical hash must be generated in the CI
container** (not on a developer laptop).

**Step A — generate + commit the canonical hash once** (run in the CI ubuntu container, or a matching pinned
container, with rust 1.96.0 + wasm-bindgen =0.2.125):

```bash
just ci-wasm                                                            # builds the .wasm
cargo run -q -p thoughtmark-cli --bin tm -- blake3 \
  packages/core/wasm/thoughtmark_wasm_bg.wasm > spec/vectors/wasm.blake3
git add spec/vectors/wasm.blake3 && git commit -m "chore(wasm): pin canonical reproducible-.wasm BLAKE3"
```

**Step B — enforce in the `conformance` job** (`.github/workflows/ci.yml`, after the `wasm-pack build` on line 74):

```yaml
      - run: wasm-pack build crates/thoughtmark-wasm --target web --out-dir ../../packages/core/wasm --out-name thoughtmark_wasm
      - run: CI=true ./scripts/assert-wasm-blake3.sh        # <-- ADD: reproducible-.wasm gate (CI enforces)
```

(`CI=true` is set by GitHub Actions automatically, so `assert-wasm-blake3.sh` enforces there and prints-and-passes
locally.)

---

## 3. `.github/workflows/ci.yml` — executor C: WASM under 3 browsers (Playwright)

**Why.** The 4th conformance executor (WASM under Chromium/Firefox/WebKit) is the empirical proof that no
float/SIMD/NaN divergence leaked across JS engines (arch §13.3). Today the `ts-wasm` job runs the `test:wasm`
placeholder (line 106). Native + Node + the pure-TS oracle already prove byte-parity; this adds the cross-engine
check. **This needs browser installs + a browser-loader test variant and could not be stood up/verified in the
agent's environment**, so it is a guided recipe.

**Recipe.**

1. Add devDeps to `packages/core/package.json`: `@vitest/browser` and `playwright`.
2. Add a browser conformance test `packages/core/test/conformance.browser.test.ts` that imports the **browser**
   loader (`../src/browser.js`, fetch-based) and loads the corpus via Vite (`import.meta.glob('/spec/vectors/**',
   { as: 'uint8array' })` or a small static-serve plugin pointing at `spec/vectors/`), then runs the same
   `runOp(op, input)` byte-comparison as `conformance.test.ts`.
3. Add `packages/core/vitest.browser.config.ts`:
   ```ts
   // SPDX-License-Identifier: Apache-2.0
   import { defineConfig } from "vitest/config";
   export default defineConfig({
     test: {
       include: ["test/**/*.browser.test.ts"],
       browser: {
         enabled: true,
         provider: "playwright",
         headless: true,
         instances: [{ browser: "chromium" }, { browser: "firefox" }, { browser: "webkit" }],
       },
     },
   });
   ```
4. Add `"test:browser": "vitest run -c vitest.browser.config.ts"` to `packages/core/package.json` scripts.
5. In the `ts-wasm` job, replace the `test:wasm` placeholder step (line 106) with:
   ```yaml
      - run: pnpm --filter @thoughtmark/core exec playwright install --with-deps chromium firefox webkit
      - run: pnpm --filter @thoughtmark/core test:browser
   ```

**Caveat (arch §13.3).** WebKit-on-Linux is heavyweight and occasionally flaky on WASM streaming-instantiate; if it
proves unstable, gate WebKit to required-on-`main` / advisory-on-PR rather than weakening the assertion.

---

## 4. `.github/workflows/nightly-fuzz.yml` — register the new fuzz targets

**Why.** Four fuzz targets landed in `fuzz/` (agent-editable): `merkle_verify`, `consistency_verify`, `dsse_parse`,
`did_key` (each asserts the no-panic wall holds on arbitrary input). The nightly smoke loop must include them.

**Change** (the `for t in jcs cid; do … done` loop):

```yaml
          for t in jcs cid merkle_verify consistency_verify dsse_parse did_key; do
            cargo +nightly fuzz run "$t" -- -runs=20000 -max_total_time=120 || true
          done
```

(Optional, arch §13.4: add the native-vs-`wasmtime` differential — run each target under `wasmtime` in
deterministic-NaN mode and assert output equality. Larger task.)

---

## 5. A Miri job on the WASM shim (`.github/workflows/` — new job or workflow)

**Why.** Miri detects UB at the C-ABI/WASM boundary that `forbid(unsafe_code)` in core cannot — and
`thoughtmark-wasm` is the one crate allowed `unsafe` (arch Domain 2; roadmap M-gates). It runs on nightly, off the
1.96.0 pin, so keep it a separate scheduled job (not the required PR wall).

```yaml
  miri-wasm-shim:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@... # (pin a SHA, like the other jobs)
        with: { persist-credentials: false }
      - uses: dtolnay/rust-toolchain@master
        with: { toolchain: nightly, components: miri }
      - run: cargo +nightly miri test -p thoughtmark-wasm     # exercises the shim's rlib on the host cfg
```

---

## 6. `deny.toml` (OPTIONAL) — silence the `cpufeatures` duplicate warning

`cargo deny check` already passes (it warns, per `multiple-versions = "warn"`). If you prefer a clean run, add the
known-benign duplicate to the skip list:

```toml
[bans]
multiple-versions = "warn"
skip = [{ crate = "cpufeatures" }]   # blake3 (0.3) vs the RustCrypto stack (0.2); unpinnable, build-detail only
```

---

## Remaining Phase-2 items deferred (not blocking the freeze candidate)

These are tracked here so nothing is silently dropped:

- **`thoughtmark-schemagen` graduation** (arch §3.5): emit `schemars` JSON-Schema + TS codegen behind the schema
  crate's `json_schema` feature. Deferred — it is a dev tool, off the freeze path, and the custom-serde wire types
  (`Digest`/`UnixMillis`/`CanonVersion`/`TreeHash`) need hand-written `JsonSchema` impls. The feature gate and stub
  are in place.
- **Cross-language `tlog-tiles` vectors (LOG-5):** `core::merkle::tiles` (`parse_tile` + the `x`-prefixed index
  path) is core-unit-tested; the cross-language tile vectors land with `TileStorage` (the public-log export driver),
  alongside the deferred `PostgresStorage` driver (Phase 5, with its DDL).
- **PostgresStorage / TileStorage drivers** (agreed deferral): the trait + `InMemoryStorage` + the pure gap-free
  `sequencer` (proptested) landed; the sqlx/object-store drivers ship with the reference app — they produce
  byte-identical roots, so they add nothing to the freeze.
- **The `byte-parity` required status check** goes fully live once items 2–3 are applied (it then spans native +
  Node + 3 browsers + oracle).
