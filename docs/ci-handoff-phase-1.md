<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase 1 — CI handoff (human-required `.github/**` edits)

`.github/**` is a protected guardrail (a human must edit it; agents cannot). Phase 1's exit gate names three CI
additions that therefore need **you** to apply them. Everything else already rides existing jobs with no YAML edit:

| Already green in existing CI (no edit) | In this handoff (needs your merge) |
|---|---|
| **Native Rust oracle** — `conformance` job already runs `cargo nextest run -p thoughtmark-testkit --test conformance` (now over real Tier-0). | **3-browser Playwright matrix** (Chromium/Firefox/WebKit) — §1. |
| **WASM-under-Node** — `conformance` job runs `pnpm … test:conformance` (rewritten, real Tier-0). | **`cargo hack --feature-powerset`** — §2. |
| **Pure-TS oracle** — new `test/oracle.conformance.test.ts` matches the `vitest run conformance` filter, so it runs inside the existing `conformance` / `ts-wasm` jobs. | **`jcs`/`cid` fuzz: native ⟷ wasmtime differential leg** — §3. |
| **`bless --check`** — wired into the `just ci-rust` recipe (`cargo run -p thoughtmark-cli -- bless --check spec/vectors`). | |

Applying these is optional for Phase 1 to be *functionally* complete (the four-executor byte-parity already runs);
they harden the exit gate to its full stated scope. SHA pins below match the rest of `.github/workflows/ci.yml`.

## 1. 3-browser conformance matrix (new job in `ci.yml`)

This runs the pure-TS oracle + the WASM/Node conformance under real browser engines via Playwright. It needs a
`test:browser` script + `@vitest/browser` / `playwright` devDeps in `packages/core` (NOT built yet — add them when
you adopt this job; keep `wasm-opt: disabled` so the artifact stays byte-stable).

```yaml
  ts-browser-conformance:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        browser: [chromium, firefox, webkit]
    steps:
      - uses: step-security/harden-runner@9af89fc71515a100421586dfdb3dc9c984fbf411 # v2.19.4
        with: { egress-policy: audit }
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with: { persist-credentials: false }
      - uses: dtolnay/rust-toolchain@3c5f7ea28cd621ae0bf5283f0e981fb97b8a7af9 # master
        with: { toolchain: "1.96.0", targets: wasm32-unknown-unknown }
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - uses: taiki-e/install-action@15449e3094499af05d8d964a1c884208e4b8b595 # v2.81.11
        with: { tool: wasm-pack }
      - uses: pnpm/action-setup@b906affcce14559ad1aafd4ab0e942779e9f58b1 # v4.3.0
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with: { node-version: 22, cache: pnpm }
      - run: wasm-pack build crates/thoughtmark-wasm --target web --out-dir ../../packages/core/wasm --out-name thoughtmark_wasm
      - run: pnpm install --frozen-lockfile
      - run: pnpm --filter @thoughtmark/core build
      - run: pnpm --filter @thoughtmark/core exec playwright install --with-deps ${{ matrix.browser }}
      - run: pnpm --filter @thoughtmark/core test:browser -- --browser.name=${{ matrix.browser }}
```

## 2. `cargo hack --feature-powerset` (append to the `rust` job's steps in `ci.yml`)

Proves every feature combination of the audited crates builds (the `vectors`/`keygen`/`std`/`alloc` matrix) — in
particular that the `vectors`-gated RNG never leaks into the default closure.

```yaml
      - uses: taiki-e/install-action@15449e3094499af05d8d964a1c884208e4b8b595 # v2.81.11
        with: { tool: cargo-hack }
      - run: cargo hack --feature-powerset --no-dev-deps check -p thoughtmark-core -p thoughtmark-schema
```

## 3. `jcs` / `cid` fuzz over real Tier-0 + wasmtime differential (edit `nightly-fuzz.yml`)

The `fuzz/fuzz_targets/{jcs,cid}.rs` targets call `thoughtmark_core::ops::run_op`, which **already executes real
Tier-0** as of Phase 1 — so the existing nightly smoke run now fuzzes the actual canonicalizer/CID encoder with no
change. The remaining exit-gate item is the **differential leg**: run each target's input through native AND
WASM-under-`wasmtime` and assert byte-equality (catching a Rust↔WASM divergence the static corpus did not
enumerate). Sketch to hand the maintainer:

```yaml
      # after the existing native `cargo +nightly fuzz run` smoke step:
      - uses: taiki-e/install-action@15449e3094499af05d8d964a1c884208e4b8b595 # v2.81.11
        with: { tool: wasmtime }
      - name: Differential jcs/cid (native vs wasmtime)
        working-directory: fuzz
        run: |
          # build the fuzz targets for wasm32-wasip1, replay the libFuzzer corpus through wasmtime,
          # and diff each output against the native run; any mismatch fails the job.
          ./scripts/fuzz-differential.sh jcs cid   # to be authored alongside this job
```

> Note: the audited core stays getrandom-free, so the wasm fuzz build uses `--no-default-features --features
> alloc` (same closure the `assert-no-getrandom-wasmbindgen.sh` gate checks).
