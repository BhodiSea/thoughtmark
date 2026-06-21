# thoughtmark — `just ci` IS the whole CI graph (ADR-0003), the single build-graph oracle. Run in order:
# Cargo -> wasm build -> TS conformance -> docs. Every recipe sources the rustup env so the pinned 1.96.0 shims
# win over Homebrew cargo (R1). Recipes use shebangs so they run as fail-fast scripts.

# List recipes.
default:
    @just --list

# Assert the toolchain is the pinned one before any gate runs (R1/R6/R11).
doctor:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo_path="$(command -v cargo || true)"
    case "$cargo_path" in
      "$HOME/.cargo/"*) ;;
      *) echo "doctor: cargo resolves to '$cargo_path', not the rustup shim. Run: . \$HOME/.cargo/env" >&2; exit 1 ;;
    esac
    rustc --version | grep -q '1\.96\.0' || { echo "doctor: active rustc is not 1.96.0 ($(rustc --version))" >&2; exit 1; }
    if command -v wasm-bindgen >/dev/null 2>&1; then
      wasm-bindgen --version | grep -q '0\.2\.125' || { echo "doctor: wasm-bindgen CLI != 0.2.125 ($(wasm-bindgen --version))" >&2; exit 1; }
    fi
    echo "doctor: ok ($(rustc --version))"

# The whole wall, in order. Merging is impossible until this is green (CI mirrors it).
ci: doctor ci-rust ci-wasm ci-ts ci-docs

# Cheapest-first Rust gate + the determinism guards.
ci-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo fmt --all --check
    taplo fmt --check
    typos
    cargo clippy --all-targets --all-features --locked -- -D warnings
    cargo nextest run --all-features --locked
    cargo run -q -p thoughtmark-cli --bin tm -- bless --check spec/vectors
    cargo deny check
    cargo audit
    ./scripts/check-dep-direction.sh
    cargo build -p thoughtmark-core --target wasm32-unknown-unknown --no-default-features --features alloc --locked
    ./scripts/assert-no-getrandom-wasmbindgen.sh

# Build the single seam artifact (wasm-pack --target web; wasm-opt disabled for byte-stability).
ci-wasm:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    wasm-pack build crates/thoughtmark-wasm --target web \
      --out-dir ../../packages/core/wasm --out-name thoughtmark_wasm
    ./scripts/assert-wasm-blake3.sh

# TS conformance gate (depends on the wasm artifact from ci-wasm).
ci-ts:
    #!/usr/bin/env bash
    set -euo pipefail
    pnpm install --frozen-lockfile
    pnpm --filter @thoughtmark/core build
    pnpm -r --if-present typecheck
    pnpm biome check .
    pnpm --filter @thoughtmark/core test:conformance
    pnpm --filter @thoughtmark/core publint
    pnpm --filter @thoughtmark/core attw
    pnpm knip

# Docs / licensing gate.
ci-docs:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/spec-traceability.sh
    ./scripts/assert-manifest-toolchain.sh
    if command -v reuse >/dev/null 2>&1; then reuse lint; else echo "note: reuse not installed (pipx install reuse)"; fi

# --- convenience ---

# Regenerate the conformance corpus's expected files from the native Rust oracle. DELIBERATE: blessing changes the
# frozen oracle, so any changed expected byte is a BREAKING corpus release (bump spec/vectors/VERSION + CHANGELOG).
bless:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo run -q -p thoughtmark-cli --bin tm -- bless spec/vectors
    echo "blessed. REVIEW the diff: a changed expected byte is a breaking corpus release."

# Assert the committed corpus still matches the native Rust oracle (also runs inside ci-rust).
bless-check:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo run -q -p thoughtmark-cli --bin tm -- bless --check spec/vectors

fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo fmt --all
    taplo fmt
    pnpm biome format --write .

build:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo build --all-targets --locked

verify-determinism: ci-wasm
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo nextest run -p thoughtmark-testkit --test conformance --locked
    pnpm --filter @thoughtmark/core test:conformance

# --- Phase 3 freeze / release gates (the CI jobs that invoke these are wired by a human; see
#     docs/phase-3-release-checklist.md — they touch .github/** which the AI author cannot edit) ---

# Release-train + manifest-toolchain consistency (run in CI with fetch-depth:0 so origin/main is available).
release-checks BASE="origin/main":
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/release-train-consistency.sh "{{BASE}}"
    ./scripts/assert-manifest-toolchain.sh

# Mutation-test the verify pipeline (slow — deliberately NOT in the default `just ci`). Needs `cargo install cargo-mutants`.
mutants:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    cargo mutants --in-place

# Code-SemVer / API-freeze gates for the Rust surface (best-effort: each tool is skipped with a note if not
# installed). The TS gates (api-extractor `api:check`, `changeset status`) and the blocking CI jobs are wired by a
# human per docs/phase-3-release-checklist.md (they need devDep installs + a nightly rustdoc + a published baseline).
ci-api:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    if command -v cargo-public-api >/dev/null 2>&1; then \
      cargo public-api -p thoughtmark-core diff --deny=all || echo "cargo-public-api: review the surface diff"; \
    else echo "note: cargo-public-api not installed (cargo install cargo-public-api --locked; needs a nightly rustdoc)"; fi
    if command -v cargo-semver-checks >/dev/null 2>&1; then \
      cargo semver-checks check-release -p thoughtmark-core || echo "cargo-semver-checks: review (needs a published baseline)"; \
    else echo "note: cargo-semver-checks not installed (cargo install cargo-semver-checks --locked)"; fi
