<!-- SPDX-License-Identifier: Apache-2.0 -->
# BOOTSTRAP — toolchain bring-up & server-side governance runbook

`just ci` is green locally against the stub crates. This runbook covers the steps that live **outside the
filesystem** (a human / GitHub admin must perform them) and the local toolchain bring-up, so a fresh machine or a
new remote reaches the same wall.

## 1. Local toolchain bring-up

```sh
# rustup shims must precede Homebrew cargo so rust-toolchain.toml (1.96.0) is honored (R1).
. "$HOME/.cargo/env"          # persisted in ~/.zshrc; verify: command -v cargo == ~/.cargo/bin/cargo
rustup toolchain install 1.96.0 --profile minimal -c rustfmt -c clippy -c rust-src -c llvm-tools-preview
rustup target add wasm32-unknown-unknown --toolchain 1.96.0

# Gate tooling (Homebrew bottles; or `cargo binstall`):
brew install just cargo-nextest cargo-deny cargo-audit taplo typos-cli wasm-pack reuse actionlint

# wasm-bindgen CLI MUST equal the crate pin (=0.2.125). wasm-pack auto-installs it; put it on PATH so
# `just doctor` asserts it:
ln -sf "$HOME/Library/Caches/.wasm-pack/wasm-bindgen-cargo-install-0.2.125/wasm-bindgen" "$HOME/.cargo/bin/wasm-bindgen"

corepack enable && pnpm install        # JS dev tooling (biome, vitest, publint, attw, knip)

just doctor && just ci                  # the whole wall
```

Optional (activate as logic lands): `cargo install cargo-vet cargo-hack cargo-semver-checks cargo-public-api cargo-mutants`; `cargo vet init` to populate `supply-chain/` exemptions; `cargo install cargo-fuzz` (nightly) for `fuzz/`.

## 2. Pin GitHub Actions to SHAs (before enabling CI) — row 15

Every third-party `uses:` in `.github/workflows/*` is currently a version tag (placeholder). Pin them to full
commit SHAs and verify:

```sh
go install github.com/suzuki-shunsuke/pinact/v3/cmd/pinact@latest   # or: brew install pinact
pinact run .github/workflows/*.yml      # tags -> SHAs (needs a GitHub token in env)
zizmor .github/workflows                 # security static-analysis (no unpinned actions, etc.)
actionlint                               # syntax + shellcheck (already green locally)
```

## 3. Repository ruleset — the authoritative wall (row 16)

CI is authoritative; the ruleset is what the AI author cannot route around. Apply via the GitHub UI
(*Settings → Rules → Rulesets*) or `gh api`. Require, on `main`:

- **Required status checks** (from `ci.yml`): `rust`, `conformance`, `ts-wasm`, `docs-licensing`,
  `actions-hardening` — merging is impossible until all are green.
- **Signed commits** (require signatures).
- **Linear history** (no merge commits) and **require a pull request before merging** (≥1 review).
- **Block force pushes** and **deletions**.
- A separate ruleset protecting **release tags** (`v*`) as immutable.

Also enable: **Secret scanning + push protection** (*Settings → Code security*) so a committed key cannot be
pushed (row 21); **CodeQL** default setup if not using the committed `codeql.yml`.

## 4. Org-level managed settings — harness lock-down (row 2)

`.claude/managed-settings.json` is a template. For it to remove the AI author's ability to weaken its own
guardrails, an administrator installs it at the OS-managed path (macOS:
`/Library/Application Support/ClaudeCode/managed-settings.json`) with `allowManagedPermissionRulesOnly` and
`strictPluginOnlyCustomization`. Verify the exact keys/path against current Claude Code docs. The committed
`.claude/settings.json` `deny` rules already block edits to `.claude/**`, `.github/**`, `deny.toml`,
`rust-toolchain.toml`, `clippy.toml` for the in-session agent; the ruleset (§3) is the real enforcement.

## 5. Deferred to later phases (wired, not yet active)

- **Reproducible-build `trim-paths`**: gated as unstable in this toolchain's cargo, so it is deferred to the
  Phase-3 release job; re-enable `[profile.release] trim-paths = "all"` once the pinned cargo stabilizes it.
- **OS sandbox**: `.claude/settings.json` ships `sandbox.enabled: false` with the correct shape
  (`sandbox.network.allowedDomains`, `sandbox.filesystem`). Verify the schema against current docs, then flip it
  to `true` — defense-in-depth atop the permission `deny` rules (CI remains the authority).
- **Browser conformance**: `wasm-bindgen-test` runs Node-only locally (no WebDriver on this machine); the
  Chromium/Firefox/WebKit matrix runs in CI (`ts-wasm` job).
- **OIDC trusted publishing** (crates.io + npm `--provenance`), SBOMs, and build attestations are wired in
  `release.yml` and activate at the Phase-3 1.0 freeze (no long-lived tokens).
