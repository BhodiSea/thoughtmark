<!-- REUSE-IgnoreStart -->
# Quality Foundations: Baseline Tooling for a Research-Tier, AI-Authored Codebase

> Pre-implementation quality contract for **thoughtmark** — the tamper-evident provenance/notarization
> library specified in [`roadmap.md`](./roadmap.md). This document defines everything that should exist in the
> repository **before the first line of implementation code is written**, so the codebase reaches and holds
> "research tier" quality even though ~100% of its code is authored by Claude Code.

---

## 0. How to read this document

This is a **decision register + checklist (Part 1)** and a **copy-paste config appendix (Part 2)**. It is written
to be executed by an AI coding agent *and* audited by a human reviewer.

**The defining constraint.** Nearly all of thoughtmark's code will be written by Claude Code, with no human
reviewing every line. Quality therefore cannot rest on human diligence at review time. It must come from
**deterministic, machine-checkable gates** that the agent cannot rationalize past, "temporarily" disable, or
silently weaken — and that fail loudly and identically whether or not the agent chooses to run them.

**The governing principle — say it once, apply it everywhere:**

> **Hooks are advisory to a cooperative agent. CI is authoritative. Every gate that exists as a Claude Code
> hook or local pre-commit step MUST also exist as a required CI check.** Hooks give the agent a fast
> feedback loop; CI is the wall the code cannot get around. If a control appears in only one of the two, treat
> it as not-yet-real.

**The honesty frame (inherited from the roadmap).** thoughtmark proves *integrity-of-record* — that a record
existed at time T, in a given lineage, unaltered since capture. It does **not** prove *validity-of-record* (that
the content is true) or *faithfulness* (that a logged chain-of-thought reflects actual computation). The quality
tooling in this document is analogously scoped: it proves the **code** is correct, deterministic, reproducible,
and auditable. It does **not**, and cannot, prove that the captured reasoning trail is true or faithful. Keep
this distinction explicit in docs and UI; never let green CI be read as a claim about the *content* being notarized.

**Priority legend:**

| Tag | Meaning |
|-----|---------|
| `[MUST]` | Establish before the first implementation PR; block merges on it. |
| `[REC]`  | Establish before the first public/tagged release. |
| `[OPT]`  | Valuable, but can land in a later roadmap phase. |

**Bootstrap order (stand the net up in this sequence so the very first code PR already runs inside it):**

1. **Governance + determinism spine** — `git init`, repository ruleset, `CLAUDE.md`, `.claude/` config + hooks,
   `rust-toolchain.toml`, `[workspace.lints]`, `clippy.toml`, `deny.toml`, `spec/vectors/` corpus skeleton,
   the cross-language conformance CI job (even against stub implementations that return "not implemented").
2. **Language tooling** — Rust test/lint stack (nextest, proptest, fuzz targets, semver-checks); TS/WASM stack
   (strict tsconfig, Biome, wasm-bindgen-test, publint/attw, knip).
3. **Supply-chain + provenance** — cargo-deny/audit/vet, CodeQL/OSV, SBOM, SLSA attestations, trusted publishing,
   OpenSSF Scorecard/Badge.
4. **Spec + docs rigor** — `SPEC.md` (BCP 14), MADR ADRs (incl. the JCS-crate decision), threat model, rustdoc +
   mdBook, REUSE/NOTICE, CITATION.cff.

A `[MUST]`→file bootstrap checklist closes Part 2.

> **A note on currency.** This document was assembled in **June 2026** from a multi-agent research pass with an
> adversarial fact-check. Tool/version facts most likely to drift (Claude Code config schema, Rust release,
> Next.js lint surface, crate maintenance status) are flagged inline with a *2026:* note. Re-verify anything
> marked "confirm against current docs" at setup time.

---

# PART 1 — Decision register & checklist

Each item: **what it does · why it matters for a trusted, AI-authored repo · the file/command · 2026 currency note.**

---

## Domain 1 — Claude Code agent harness (`.claude/`)

*Why this domain matters:* this is the layer that keeps the primary author (an AI agent) on-rails. It is the
first reviewer and the fast feedback loop — but it is **advisory**, so everything here is mirrored by CI (Domain 5).

- **`CLAUDE.md` (project root)** `[MUST]` — The determinism/security codebook loaded into every session.
  Contains: the architecture map (Rust core → WASM/TS bindings → reference app); the **invariants** (byte-identical
  output across languages, JCS-before-hash, no ambient nondeterminism, salted hashes only, off-chain content);
  a **never-do list** (mutate or `.skip()` a test to make it pass, weaken a lint/deny rule, add a dependency
  without `cargo deny` review, hand-roll crypto, push to a protected branch); the exact **build/test/lint
  commands**; and a written **Definition of Done**. Keep it tight (~200–250 lines) and link out to `.claude/rules/`.
  *Why:* prevents agent drift — every session inherits the same constraints instead of re-deriving them.
  *2026:* `CLAUDE.md` is the canonical project-memory file; `AGENTS.md` is the cross-tool equivalent many tools
  read — keep `CLAUDE.md` as source of truth and, if you want cross-tool portability, make `AGENTS.md` a symlink
  or thin pointer rather than a fork. Pair with Claude Code's auto-memory for *discovered* quirks; keep
  human-authored invariants in `CLAUDE.md`.

- **`.claude/rules/*.md` with `paths:` frontmatter** `[REC]` — Modular instruction files that load only when the
  agent touches matching files (`crypto-invariants.md` → `src/**/crypto/**`, `wasm-determinism.md` → `bindings/**`,
  `testing.md` → `tests/**`). *Why:* keeps `CLAUDE.md` compact and puts crypto-specific rules in context exactly
  when crypto code is being edited, without burning tokens elsewhere.

- **`.claude/settings.json` (committed)** `[MUST]` — Team-shared permissions, env, hooks, sandbox.
  Permissions use **three ordered rule lists: `deny` → `ask` → `allow`** (first match wins; a `deny` at *any*
  settings scope blocks). Pre-approve safe, auditable commands in `allow`; route irreversible/outward-facing ops
  to `ask`; hard-block dangerous ones in `deny`. Set `env` (`RUSTFLAGS=-D warnings`, `RUST_BACKTRACE=1`).
  *Why:* removes whole classes of mistakes at the tool layer, below where the agent can reason about them.
  *2026 (correction):* the model is **not** a two-way "deny beats allow" merge — it is **deny/ask/allow evaluated
  in order**. Don't gate these on a specific version number; the three-list model predates recent releases.
  Keep personal-only overrides (e.g. a looser local mode) in **`.claude/settings.local.json`** (gitignored).

- **Sandboxing (`sandbox` in settings.json)** `[MUST]` — OS-level filesystem/network confinement for `Bash`.
  *Why:* it is the **only** layer that still holds if a prompt-injection or model error slips past the permission
  rules — arguably more important than any single hook for a security-sensitive, key-handling repo. Enable it and
  allowlist just the network egress the build genuinely needs. *2026:* confirm the exact `sandbox.*` schema
  against current Claude Code docs at setup time; treat permissions + sandbox as defense-in-depth, not either/or.

- **Harness lock-down** `[MUST]` — Stop the agent from weakening its own guardrails. `deny` rules for
  `Edit(.claude/**)`, `Edit(.github/**)`, `Edit(deny.toml)`, `Edit(rust-toolchain.toml)`, and reads of secrets
  (`Read(./.env*)`, `Read(./**/*.key)`, `Read(./secrets/**)`). Consider org-level **`managed-settings.json`**
  with `allowManagedPermissionRulesOnly` / `strictPluginOnlyCustomization` so guardrail edits require a human.
  *Why:* if the author can edit the rules that constrain it, the rules are theatre. CI (Domain 5) is the real
  enforcement, but locking the config removes the temptation and the foot-gun. *2026:* verify the managed-settings
  key names against current docs.

- **Hooks** `[MUST]` — Deterministic checks wired to tool events.
  - **`PreToolUse`** is the **true blocking gate**: a guard that inspects a pending `Bash`/`Edit` and can refuse it
    *before* it runs (e.g. block `git push --force`, edits to protected files, `curl … | sh`).
  - **`PostToolUse`** runs *after* the tool has already executed, so it **cannot undo** the action — it
    auto-formats and surfaces lint/test output back to the agent as follow-up work. Use it for `cargo fmt` +
    `clippy` + fast targeted tests after an edit; keep it fast.
  - Use `SessionStart`/`Stop` hooks to record which `CLAUDE.md`, rules, and skills actually loaded — a cheap
    determinism/audit trail for an agent-built repo.
  *Why:* fast, machine-checkable feedback without waiting for CI. *2026 (correction):* don't rely on `PostToolUse`
  "exit 2 blocks" — it surfaces stderr, it does not roll back. The per-handler `if` condition lives on the
  individual **hook handler**, not on the matcher. **Every hook here is also a CI check.**

- **Reviewer subagent `.claude/agents/crypto-verifier.md`** `[REC]` — An adversarial reviewer invoked on
  crypto/canonicalization changes (determinism, invariant violations, weak tests). *Why:* a useful backstop —
  but a **backstop, never the primary gate**; the deterministic gates are. *2026 (correction):* subagent
  frontmatter uses **`tools:`** (a list), **not** `allowedTools`. Valid fields include `description`, `tools`,
  `disallowedTools`, `model`, `permissionMode`, `mcpServers`, `hooks`. Pin `model: opus` (alias), not a made-up
  selector.

- **Skills `.claude/skills/<name>/SKILL.md`** `[REC]` — Repeatable workflows: `verify-determinism` (run the full
  cross-language vector suite), `test-all`, `audit-deps`. *Why:* turns multi-step quality routines into one
  invocation the agent (or human) can call consistently. *2026 (correction):* real frontmatter is `name`,
  `description`, `when_to_use`, `disable-model-invocation` (bool), `user-invocable` (bool), `allowed-tools`,
  `arguments` — there is **no** `invokeOn`/`invokeLimit`. Custom `.claude/commands/*.md` are now the **legacy**
  surface (merged into skills); prefer a skill, and if a command and skill share a name the skill wins.

- **`.mcp.json`** `[OPT]` — Project-scoped MCP servers (a Supabase MCP is already available in this environment).
  Scope to what the reference app needs; keep it out of the core crate's workflow.

---

## Domain 2 — Rust core quality & correctness

*Why this domain matters:* the Rust core is the audited, trusted primitive. Strict compilation and lints are the
**first reviewer** — they make hallucinated APIs, sloppy error handling, and nondeterminism fail to *compile*.

- **`rust-toolchain.toml` (pinned)** `[MUST]` — Pin `channel = "1.96.0"`, `edition 2024`, components
  `rustfmt, clippy, rust-src, llvm-tools-preview`. *Why:* "reproducible/deterministic build" claims are
  unenforceable without a pinned toolchain across every machine and CI. *2026:* Rust **stable is 1.96.0**
  (released 2026-05-28) as of this writing. Tools that need **nightly** (cargo-fuzz, Miri, cargo-careful) should
  use a **separate dated nightly** in their CI jobs — do not pin the whole repo to nightly.

- **`[workspace.lints]` with deny-warnings** `[MUST]` — In root `Cargo.toml`: deny `clippy::all`,
  `clippy::pedantic`, `clippy::cargo`, plus a curated set of **restriction** lints in crypto paths
  (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `float_arithmetic`). `RUSTFLAGS=-D warnings` in CI.
  *Why:* an AI author will reach for `.unwrap()` and `a[i]`; denying them forces explicit, panic-free handling and
  bans floating-point from the hash path at compile time.

- **`#![forbid(unsafe_code)]`** `[MUST]` — Forbid unsafe in the core (allow narrowly, audited, only in the FFI/WASM
  shim crate). *Why:* removes the largest class of memory-safety findings before an audit and shrinks the trusted
  surface. Pair with `cargo-geiger` to track any unsafe that does exist.

- **`clippy.toml` `disallowed-methods`** `[MUST]` — Ban ambient nondeterminism in core logic:
  `std::time::SystemTime::now`, `Instant::now`, `rand::thread_rng`. *Why:* determinism is the project's central
  correctness property; enforce it as a lint, not a code-review hope. Inject time/RNG explicitly through APIs.

- **`rustfmt.toml` + `taplo` + `typos`** `[MUST]` — Deterministic formatting for `.rs` and `.toml`, plus
  spell-checking (`crate-ci/typos`). *Why:* zero-diff formatting and no embarrassing typos in a citeable artifact;
  `--check` variants run in CI.

- **Test runner: `cargo-nextest`** `[MUST]` — Process-per-test isolation, flaky-test retries, JUnit output, ~60%
  faster. *Why:* isolation means one panicking test can't mask others — important when an AI may write many tests
  at once; speed serves the fast-feedback constraint.

- **Property-based testing: `proptest`** `[MUST]` — Encode invariants as properties: `canonicalize` is
  idempotent; `hash(canonicalize(x))` is stable; an inclusion proof verifies **iff** the leaf is in the tree.
  *Why:* catches whole input classes that example-based (and shallow AI-written) tests miss.

- **Mutation testing: `cargo-mutants`** `[REC]` — Mutates the code and checks the tests catch it. *Why:* directly
  measures whether AI-written tests actually *constrain* behavior rather than just executing it. Coverage % alone
  is weak assurance for near-100% AI-authored code.

- **Golden snapshots: `insta`** `[REC]` — Snapshot canonical bytes / proof structures. *Why:* any byte-level drift
  in serialization surfaces as a reviewable snapshot diff.

- **Fuzzing: `cargo-fuzz` (libFuzzer) / `bolero`** `[MUST]` — Coverage-guided fuzz targets on the **JCS
  canonicalizer, all parsers, the CID encoder, and the proof verifiers**. *Why:* these untrusted-input boundaries
  are exactly where a provenance library must not panic or accept malformed input; for a crypto crate fuzzing is
  baseline, not optional. (Nightly job; optionally with `-Zsanitizer`.)

- **Model checking: `Kani`** `[OPT]` — Bounded proofs of canonicalization round-trip / proof-verifier soundness.
  *Why:* the strongest assurance for the few truly load-bearing functions; reserve for those.

- **UB detection: `Miri` + `cargo-careful`** `[REC]` — Run the FFI/WASM-shim crate's tests under Miri and
  careful (nightly). *Why:* catches UB at the C-ABI/WASM boundary that `forbid(unsafe_code)` in the core can't.

- **Benchmarks: `criterion`** `[OPT]` — Track performance/regressions (hashing, Merkle ops). *Why:* prevents an
  AI refactor from silently making the hot path 10× slower.

- **API stability: `cargo-semver-checks` + `cargo-public-api`** `[REC]` — Mechanically catch breaking public-API
  changes; produce a human-reviewable API diff in PRs. *Why:* a library shipping a stable spec + conformance
  vectors must not break its API by accident; the API diff is the cheapest human-review surface for an AI's edits.

- **Hygiene: `cargo-hack`, `cargo-machete`, `cargo-msrv`** `[REC]` — Feature-combination build matrix; unused-dep
  detection; MSRV verification. *Why:* keeps the dependency/feature surface minimal and auditable.

---

## Domain 3 — TypeScript / WASM bindings & Next.js app

*Why this domain matters:* the WASM/TS binding must produce **byte-identical** output to the Rust core. The TS
toolchain must be as strict and machine-checkable as the Rust one, or the weakest language sets the trust level.

- **pnpm + corepack + `packageManager` pin** `[MUST]` — Pin the exact pnpm version via `packageManager` and
  corepack; commit the lockfile; CI uses `--frozen-lockfile`; enable a `minimumReleaseAge` supply-chain cooldown.
  *Why:* the agent and CI must never drift package managers or pull a just-published malicious version.

- **Strictest TypeScript** `[MUST]` — Extend `@tsconfig/strictest`; explicitly add `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `erasableSyntaxOnly`. Run **`tsc --noEmit` as its own CI step**. *Why:* the type
  system is the TS-side "first reviewer"; `tsc` is a real typechecker and **Biome's inference does not replace it**.

- **Biome v2 (primary lint + format)** `[MUST]` — Rust-native, deterministic, type-aware, with GritQL custom
  rules. *Why:* one fast, deterministic tool for lint+format across the bindings. *2026 (correction):* keep
  **ESLint (flat config, `eslint-config-next`) only for the Next.js app**, and run it directly — **`next lint`
  is removed in Next.js 16** (and the `eslint` key in next config is no longer needed). Confirm whether the app is
  on Next 15 (deprecated `next lint`) or 16 (removed).

- **Vitest** `[MUST]` — Unit/integration tests; the load-bearing one is the **shared cross-language conformance
  suite** (Domain 4) run from the TS side. *Why:* proves the binding matches the Rust core, not just "passes."

- **wasm-pack + `wasm-bindgen-test`** `[MUST]` — Build the WASM and run its tests in CI across **Node and a
  headless browser** (and a Node WASI target if used). *Why:* byte-identical hashing must hold across JS runtimes,
  not just one; browser/Node float and encoding behavior can differ.

- **Package correctness: `publint` + `@arethetypeswrong/cli`** `[MUST]` — Validate `exports`, types resolution,
  ESM/CJS, dual-package correctness before publish. *Why:* a subtly broken `@thoughtmark/core` package undermines
  adoption and trust regardless of how good the core is.

- **`knip` (dead code / unused deps)** `[REC]` — *Why:* AI authors accrete unused exports and dependencies; knip
  keeps the TS surface and supply chain minimal and auditable.

- **`type-coverage` ratchet** `[REC]` — Enforce a rising floor of explicit typing (no silent `any`). *Why:* keeps
  the type net from eroding as the agent adds code.

- **`size-limit`** `[OPT]` — Bundle/`.wasm` size budget for the browser package. *Why:* catches accidental bloat.

- **Next.js / Supabase baseline** `[REC]` — Row-Level Security on every table; `supabase gen types typescript`
  checked into CI; run Supabase advisors; **service-role keys server-side only**. *Why:* the reference app is a
  *demo of the library's trust story* — it must not undercut it with a leaky data layer.

---

## Domain 4 — The cross-language determinism harness  ⭐ *single most load-bearing control*

*Why this domain matters:* "byte-identical hashes across Rust and `@thoughtmark/core`" is the project's central
correctness claim. It deserves its own gate, wired **before** implementation — not an afterthought folded into
unit tests.

- **Committed conformance-vector corpus (`spec/vectors/`)** `[MUST]` — Language-agnostic JSON vectors: canonical
  JSON inputs → expected canonical UTF-8 bytes (hex), `BLAKE3`, `SHA-256`, `CIDv1`, plus Ed25519/DSSE and Merkle
  inclusion/consistency vectors. Each vector carries a stable `vector_id`, the `SPEC.md` requirement ID it
  exercises, and a `canon_version`. *Why:* the corpus *is* the executable spec; it is checked into the repo and
  versioned independently (Domain 8).

- **Differential CI job: Rust ⟷ WASM/TS** `[MUST]` — A required job that runs the **same** corpus through the
  Rust core **and** the compiled WASM/TS binding and asserts **byte-equality** of every output. *Why:* this is
  the gate that makes the cross-language guarantee real; it should exist (against stubs) from the first PR.

- **Forbid floating point in the canon/hash/CID path** `[MUST]` — Enforced by the `clippy::float_arithmetic`
  restriction lint (Domain 2). *Why:* WebAssembly has documented NaN-bit nondeterminism; the only safe baseline
  is to keep floats entirely out of JCS number handling and CIDv1 varint encoding. (WASM 3.0's deterministic
  profile is helpful context, not a substitute.)

- **Versioned `canon_version` + fail-closed negative vectors** `[REC]` — Bake a canonicalization-version tag into
  the hashed bytes, and include negative vectors proving a version mismatch **fails closed**. *Why:* lets retained
  artifacts stay verifiable across future canonicalization-rule changes without silent ambiguity.

- **Differential fuzzing (Rust vs WASM)** `[OPT]` — Fuzz both implementations on the same inputs and diff outputs.
  *Why:* finds divergences the static corpus didn't enumerate.

- **Surface as `/verify-determinism` skill** `[REC]` — One agent/human invocation runs the whole harness.
  *Why:* makes "did I keep the vectors green?" a single, habitual command.

---

## Domain 5 — CI/CD & repository governance

*Why this domain matters:* CI is the **authoritative** enforcement layer (every hook/local check is mirrored
here). Governance choices front-load supply-chain integrity so no human has to review every line.

- **GitHub Actions, all third-party actions SHA-pinned** `[MUST]` — Pin to full commit SHAs (not tags); verify
  with **`zizmor`** (security static-analysis), **`pinact`** (pin enforcement), and **`actionlint`** (syntax +
  shellcheck). Add **StepSecurity `harden-runner`** for egress auditing and least-privilege `permissions:` blocks.
  *Why:* CI is part of the trusted supply chain of a notarization library; an unpinned action is an upstream
  takeover vector.

- **Multi-OS / multi-Rust matrix** `[MUST]` — `stable` + MSRV (+ `nightly` allowed-to-fail) via
  `dtolnay/rust-toolchain` and `Swatinem/rust-cache`; include a `wasm32-unknown-unknown` (and WASI if used) build.
  *Why:* proves the WASM core compiles and passes on the real target, and that hashes hold across platforms.

- **Required checks (the gate set)** `[MUST]` — `cargo fmt --check`, `clippy -D warnings`, `cargo nextest run`,
  the **conformance/determinism job**, `cargo deny check`, `cargo audit`, `tsc --noEmit`, `biome check`,
  `wasm-bindgen-test`, `publint`/`attw`. *Why:* this is the wall; merging is impossible until it's green.

- **Repository rulesets (not legacy branch protection)** `[MUST]` — Require the named status checks, **signed
  commits**, linear history, and PR review; protect **release tags** (immutable). *Why:* immutable, signed history
  is part of the provenance trust model the project itself sells.

- **Local gating mirrors CI: `lefthook` (or `pre-commit`/`prek`) + a `just`/`cargo-make` `ci` task** `[MUST]` —
  The same fmt/clippy/deny/typos/biome gates run pre-commit and pre-push, and `just ci` runs the exact CI graph
  locally. *Why:* protects non-agent commits too, and gives the agent the identical gate locally — fast loop,
  no surprises at CI.

- **Conventional Commits + commitlint** `[REC]` — Enforce on PR titles/commits. *Why:* drives automated changelog
  and SemVer decisions; keeps an AI's commit stream legible.

- **Release automation: `release-plz` (Rust) + `changesets` (npm)** `[REC]` — `release-plz` integrates
  `cargo-semver-checks` to block accidental SemVer breaks; `changesets` versions `@thoughtmark/core`. Keep a
  **Keep a Changelog**-format `CHANGELOG.md`. *Why:* deterministic, reviewable releases for both ecosystems.

- **Dependency automation: `Renovate` (or Dependabot)** `[REC]` — For Cargo + Actions + npm, with cooldown /
  minimum-release-age; gate the resulting PRs through `cargo-deny`/`cargo-vet`. Add `actions/dependency-review-action`
  on PRs. *Why:* an AI won't proactively patch advisories; automation + policy keeps the posture current safely.

- **Repo hygiene files** `[MUST]` — `.editorconfig`, `.gitignore`, `.gitattributes` (LF normalization,
  `*.wasm binary`), `CODEOWNERS`, issue/PR templates. *Why:* baseline consistency and routing.

---

## Domain 6 — Crypto & security controls

*Why this domain matters:* this is a cryptographic, key-handling library headed for external audit. These
controls are what an auditor will look for first.

- **Audited crates, pinned** `[MUST]` — `ed25519-dalek` (always `verify_strict`), `sha2`, `blake3`, RustCrypto
  formats. *Why:* never hand-roll crypto; `verify_strict` rejects the Ed25519 malleability/cofactor edge cases.

- **Constant-time & key-hygiene discipline: `subtle`, `zeroize`, `secrecy`** `[MUST]` — Constant-time
  equality/selection; wipe key material on `Drop`; wrap secrets in `Secret<T>`. *Why:* mandatory baseline for a
  signing/key-handling library; encode as design rules from commit zero. *(`dudect`-style timing tests: `[OPT]`.)*

- **Authoritative test vectors** `[MUST]` — Import **Wycheproof** (Ed25519, incl. malleability), RFC 8032,
  RFC 6962/9162 (Merkle), DSSE PAE, RFC 8785 (JCS), and multiformats/CID vectors — not hand-made ones. *Why:* the
  whole point of a conformance library is conforming to the authorities; their vectors are the oracle.

- **Secret scanning: `gitleaks` + GitHub secret scanning + push protection** `[MUST]` — Plus `.gitignore` and
  `deny` rules for `*.key`/`.env*`. *Why:* an Ed25519/DSSE library will generate and handle private keys; a
  committed key is catastrophic and must be impossible to push.

- **Code scanning: `CodeQL` + `OSV-Scanner`** `[REC]` — CodeQL (now GA for Rust) on the core; OSV-Scanner across
  cargo **and** npm with SARIF upload. *Why:* automated detection across both ecosystems for an auditable library.

- **Dependency policy/audit: `cargo-deny` + `cargo-audit`/`cargo-auditable` + `cargo-vet`** `[MUST]` —
  `cargo-deny` enforces advisories/licenses/bans/sources policy; `cargo-audit` checks the RustSec DB;
  `cargo-auditable` embeds the dep manifest into shipped artifacts so they stay CVE-scannable post-hoc;
  **`cargo-vet`** records human/trusted audits of dependency *source* (import Mozilla/Google audit sets).
  *Why:* policy + provenance + post-hoc scannability is the full supply-chain story an audit expects.
  *2026:* `cargo-vet` (Mozilla, actively maintained) is the 2026 org-standard for audit enforcement, **preferred
  over `cargo-crev`**; `cargo-deny` and `cargo-vet` are complementary, not redundant.

- **Threat model doc (`docs/threat-model.md`)** `[MUST]` — State exactly what the system **proves**
  (integrity-of-record, append-only consistency, signer identity) vs **does NOT prove** (faithfulness/validity of
  the reasoning; split-view resistance without gossip/witnesses; truth-at-capture / the oracle problem). *Why:*
  this is a must-have audit-readiness artifact and the written form of the honesty frame in §0.

- **Implementation-risk flag — anchoring (`[OPT]` Tier-2 work, but record now)** — The roadmap names OpenTimestamps
  and RFC 3161 anchoring. *2026 reality check to capture in an ADR:* `rust-opentimestamps` (0.7.2) only
  **parses/serializes** `.ots` and replays hashes — it does **not** do calendar-server stamping or
  upgrade/verification, so the OTS plugin must implement the calendar protocol or shell out. RFC 3161 has a
  pure-Rust path via **`x509-tsp`** (+ RustCrypto `tsp-asn1`). Anchoring is **less turn-key in Rust than the
  roadmap implies**; treat it as an implementation-risk gap, not a drop-in dependency.

---

## Domain 7 — Reproducibility, release provenance & supply chain (dogfood the mission)

*Why this domain matters:* a library that sells reproducibility and offline verifiability must demonstrably have
those properties for **its own** releases. This is credibility, not box-ticking.

- **Reproducible builds** `[MUST]` — Commit `Cargo.lock`; build `cargo build --locked --frozen`; set
  `SOURCE_DATE_EPOCH`; use **`[profile.release] trim-paths = "all"`** for path normalization; pin the toolchain
  (Domain 2); **pin the `wasm-opt`/binaryen version** (its output is not stable across versions). Add a CI job that
  **rebuilds and diffs the artifact / `.wasm` hash**. *Why:* turns "reproducible" from a claim into a passing check.
  *2026 (correction):* use Cargo's **`trim-paths`** (RFC 3127, stable since Rust 1.81) — **not** hand-rolled
  `--remap-path-prefix`. Full turnkey reproducibility is still maturing upstream (`rust-lang/rust#129080`); verify
  determinism on Linux CI, where the gaps are smallest.

- **SBOMs** `[REC]` — `cargo-cyclonedx` (Rust) and `@cyclonedx/cyclonedx-npm` (TS) emitted and attached on release.
  *Why:* expected for an audited security library and for the SLSA/standardization story.

- **Release provenance & signing** `[REC]` — GitHub **Artifact Attestations** (SLSA build provenance via
  Sigstore); **crates.io Trusted Publishing (OIDC)** and **npm Trusted Publishing (OIDC) + `npm publish
  --provenance`** — **no long-lived `NPM_TOKEN`/PAT**. Add a **consumer-side verify** step (`npm audit signatures`,
  `cosign verify`). *Why:* prove provenance *and* verify it, mirroring what the library asks its users to do.

- **OpenSSF Scorecard + Best Practices Badge** `[REC]` — Scorecard action (≈18 checks) and the OpenSSF Best
  Practices badge in the README. *Why:* a standard, externally legible trust signal for an open-source crypto lib.

---

## Domain 8 — Research-tier docs & specification rigor

*Why this domain matters:* the deliverable is a *credibility artifact* aiming at eventual IETF-style
standardization. The spec and the conformance suite are first-class deliverables, on equal footing with code.

- **`SPEC.md` (normative)** `[MUST]` — Use **BCP 14** (RFC 2119 + RFC 8174) requirement keywords with **stable
  per-requirement IDs** (e.g. `CANON-3`, `LOG-7`) traced **bidirectionally** to tests/vectors. *Why:* makes the
  spec testable and the tests spec-anchored; this traceability is the backbone of a conformance claim.

- **Conformance corpus as a versioned deliverable** `[MUST]` — `spec/vectors/` gets its **own SemVer** and an
  **append-only changelog**; changing any expected hash is a **breaking spec change**. *Why:* prevents the vectors
  from silently drifting away from `SPEC.md`.

- **ADRs in MADR format (`docs/adr/`)** `[MUST]` — Record load-bearing decisions, including a **day-one ADR
  pinning the JCS crate**. *2026 (correction):* **`serde_jcs` is abandoned and has known RFC 8785 divergences** —
  use the maintained **`serde_json_canonicalizer`** (evik42, updated Feb 2026), with version pinned and behavior
  locked by the conformance vectors. *Why:* for a byte-identical-hash library the canonicalizer choice *is* a
  spec/reproducibility decision and must be recorded and justified.

- **Docs site: rustdoc + mdBook** `[REC]` — `#![deny(missing_docs)]` for the API; **mdBook** (idiomatic for Rust;
  prefer it over mkdocs-material) for the guide/spec. The eventual Internet-Draft is authored later in
  **`kramdown-rfc`**. *Why:* complete, deny-on-missing API docs plus a real guide are table stakes for adoption.

- **Citeability: `CITATION.cff` + GitHub↔Zenodo DOI** `[REC]` — *Why:* a research artifact must be citeable with a
  stable DOI.

- **Licensing compliance: REUSE/SPDX + `NOTICE`** `[MUST]` — Per-file `SPDX-License-Identifier: Apache-2.0`
  headers (lint with `reuse`), plus an Apache-2.0 **`NOTICE`** file (Apache-2.0 requires NOTICE handling, not just
  SPDX headers). *Why:* clean licensing matters doubly given the patent-grant rationale and FTO concerns in the
  roadmap.

- **`SECURITY.md` + `CONTRIBUTING.md` + RFC/design-doc process** `[MUST]` — Private vuln-disclosure policy
  (with RUSTSEC coordination) and a lightweight written process for normative changes. *Why:* expected baseline
  for a security-sensitive OSS project and a prerequisite for outside trust.

- **Independent-rebuild story** `[OPT]` — A documented `rebuild.sh` + expected-hash manifest (and/or a `diffoscope`
  workflow) so a third party can reproduce hashes offline. *Why:* the strongest possible form of "trust us": don't.

---

# PART 2 — Config appendix (copy-paste-ready)

> These are **starting templates**, deliberately minimal and current to mid-2026. Pin exact versions/SHAs at
> setup, and re-verify anything marked "confirm against current docs." Files not shown in full are specified by
> their key settings in Part 1.

### `CLAUDE.md` (skeleton)

```markdown
# thoughtmark — agent codebook

## What this is
Tamper-evident provenance library for human–AI reasoning trails.
Rust core (`thoughtmark-core`) → WASM/TS bindings (`@thoughtmark/core`) → Next.js/Supabase reference app.
License: Apache-2.0. This code is authored almost entirely by Claude Code. CI is authoritative.

## Invariants (NEVER violate)
- Outputs MUST be byte-identical across the Rust core, WASM, and TS. The `spec/vectors/` corpus is the oracle.
- ALWAYS canonicalize JSON via RFC 8785 JCS (`serde_json_canonicalizer`) before hashing.
- NO ambient nondeterminism in core logic: no `SystemTime::now`, `Instant::now`, `thread_rng`. Inject time/RNG.
- NO floating point anywhere in the canonicalization / hashing / CID path.
- Store only salted hashes; NEVER store sensitive content or put content on any chain.
- Crypto via audited crates only (`ed25519-dalek` with `verify_strict`, `sha2`, `blake3`). Never hand-roll.

## Never do
- Mutate, `.skip()`, or `#[ignore]` a test to make it pass.
- Weaken a lint, a `deny.toml` rule, a hook, or a CI gate. Edits to `.claude/**`, `.github/**`,
  `deny.toml`, `rust-toolchain.toml` require a human.
- Add a dependency without `cargo deny check` (and a `cargo vet` entry).
- Push to a protected branch or force-push.

## Build / test / lint (run before every commit)
- `just ci`  # = fmt --check, clippy -D warnings, nextest, conformance, deny, audit, tsc, biome, wasm tests

## Definition of Done
A change is done when: it compiles with `-D warnings`; clippy (all/pedantic/cargo) is clean; the cross-language
conformance vectors are byte-identical; new behavior has proptest + example tests; public-API changes pass
`cargo-semver-checks`; docs build with no missing-docs; and `just ci` is green locally.
```

### `.claude/settings.json` (committed)

```json
{
  "permissions": {
    "defaultMode": "plan",
    "deny": [
      "Bash(git push --force*)",
      "Bash(rm -rf*)",
      "Bash(sudo*)",
      "Bash(curl*| sh)",
      "Bash(curl*| bash)",
      "Read(./.env*)",
      "Read(./secrets/**)",
      "Read(./**/*.key)",
      "Edit(./.claude/**)",
      "Edit(./.github/**)",
      "Edit(./deny.toml)",
      "Edit(./rust-toolchain.toml)"
    ],
    "ask": [
      "Bash(git push*)",
      "Bash(cargo publish*)",
      "Bash(npm publish*)",
      "Bash(gh *)"
    ],
    "allow": [
      "Bash(cargo build*)",
      "Bash(cargo nextest run*)",
      "Bash(cargo clippy*)",
      "Bash(cargo fmt*)",
      "Bash(cargo deny*)",
      "Bash(cargo audit*)",
      "Bash(just *)",
      "Bash(pnpm *)",
      "Bash(git status)",
      "Bash(git diff*)",
      "Bash(git add*)",
      "Bash(git commit*)",
      "Read(./**)",
      "Edit(./src/**)",
      "Edit(./bindings/**)",
      "Edit(./tests/**)",
      "Edit(./spec/**)",
      "Edit(./docs/**)"
    ]
  },
  "env": { "RUSTFLAGS": "-D warnings", "RUST_BACKTRACE": "1" },
  "sandbox": {
    "enabled": true,
    "network": { "allow": ["crates.io", "static.crates.io", "registry.npmjs.org", "github.com"] }
  },
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "./.claude/hooks/guard-bash.sh" } ] }
    ],
    "PostToolUse": [
      { "matcher": "Edit|Write", "hooks": [ { "type": "command", "command": "./.claude/hooks/fmt-lint.sh" } ] }
    ]
  }
}
```
> *Permissions evaluate `deny` → `ask` → `allow`, first match wins; a `deny` at any scope blocks. Confirm the
> exact `sandbox.*` schema against current Claude Code docs at setup. Keep personal overrides in
> `.claude/settings.local.json` (gitignored).*

### `.claude/rules/crypto-invariants.md` (path-scoped rule)

```markdown
---
paths:
  - "src/**/crypto/**/*.rs"
  - "src/**/canon*.rs"
  - "src/**/hash*.rs"
---
# Crypto & canonicalization invariants
- Canonicalize via `serde_json_canonicalizer` (RFC 8785) before any hash. Never re-implement JCS.
- BLAKE3 (`blake3`) is the internal default; SHA-256 (`sha2`) for interop. Both must be in the vectors.
- Ed25519 via `ed25519_dalek`, verification ALWAYS `verify_strict`.
- No floats; no `SystemTime`/`thread_rng`. Wrap secrets in `secrecy::Secret`, wipe with `zeroize`.
- Every new primitive ships with authoritative test vectors (Wycheproof / RFC) AND a `spec/vectors/` entry.
```

### `.claude/agents/crypto-verifier.md` (reviewer subagent — corrected frontmatter)

```markdown
---
name: crypto-verifier
description: Adversarial reviewer for crypto/canonicalization changes. Checks determinism, invariant violations, and whether tests actually constrain behavior. Backstop, never the primary gate.
tools: Read, Grep, Bash
model: opus
permissionMode: default
---
Review the diff for: float usage or ambient nondeterminism in the canon/hash/CID path; missing or shallow tests
(would `cargo-mutants` survive?); missing `spec/vectors/` entries for new behavior; hand-rolled crypto; non-strict
Ed25519 verification. Report findings; do not edit. The deterministic CI gates remain authoritative.
```

### `.claude/skills/verify-determinism/SKILL.md` (corrected frontmatter)

```markdown
---
name: verify-determinism
description: Run the full cross-language conformance suite and assert byte-identical Rust <-> WASM/TS output.
when_to_use: Before any commit touching canonicalization, hashing, CID, the Merkle log, or the bindings.
disable-model-invocation: false
user-invocable: true
allowed-tools: Bash
---
1. `cargo nextest run -p thoughtmark-core --test conformance`
2. `pnpm --filter @thoughtmark/core test:conformance`
3. Compare both runs' outputs against `spec/vectors/`; FAIL on any byte divergence and print the first mismatch.
```

### `rust-toolchain.toml`

```toml
[toolchain]
channel    = "1.96.0"
components = ["rustfmt", "clippy", "rust-src", "llvm-tools-preview"]
profile    = "minimal"
```

### Root `Cargo.toml` — `[workspace.lints]`

```toml
[workspace.lints.rust]
unsafe_code   = "forbid"
missing_docs  = "warn"
unreachable_pub = "warn"

[workspace.lints.clippy]
all      = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
cargo    = { level = "deny", priority = -1 }
# restriction lints (enforced in crypto paths; relax per-crate only with justification)
unwrap_used      = "deny"
expect_used      = "deny"
panic            = "deny"
indexing_slicing = "deny"
float_arithmetic = "deny"

[profile.release]
trim-paths = "all"   # RFC 3127 — reproducible paths (stable since 1.81). Do NOT hand-roll --remap-path-prefix.
```

### `clippy.toml`

```toml
disallowed-methods = [
  { path = "std::time::SystemTime::now", reason = "non-deterministic; inject a clock explicitly" },
  { path = "std::time::Instant::now",    reason = "non-deterministic" },
  { path = "rand::thread_rng",           reason = "ambient RNG; pass an explicit CSPRNG" },
]
```

### `deny.toml` (cargo-deny)

```toml
[advisories]
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked  = "deny"

[licenses]
allow = ["Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "Unicode-3.0"]
confidence-threshold = 0.93

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```
> *Also enable `cargo-vet` (`supply-chain/config.toml` + `audits.toml`, importing Mozilla/Google audit sets) and
> `cargo-audit`/`cargo-auditable`. cargo-deny syntax: confirm against the installed v0.16+/v2 schema.*

### `tsconfig.json`

```json
{
  "extends": "@tsconfig/strictest/tsconfig.json",
  "compilerOptions": {
    "module": "nodenext",
    "moduleResolution": "nodenext",
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "erasableSyntaxOnly": true,
    "verbatimModuleSyntax": true,
    "noEmit": true
  }
}
```

### `biome.json`

```json
{
  "$schema": "https://biomejs.dev/schemas/2.0.0/schema.json",
  "linter": { "enabled": true, "rules": { "recommended": true } },
  "formatter": { "enabled": true, "indentStyle": "space", "indentWidth": 2 },
  "assist": { "actions": { "source": { "organizeImports": "on" } } }
}
```
> *Biome is the primary lint+format for the bindings. Run `tsc --noEmit` separately (Biome ≠ typechecker). Keep
> ESLint (`eslint-config-next`, flat config) only for the Next.js app — `next lint` is removed in Next 16.*

### `package.json` (key fields)

```json
{
  "packageManager": "pnpm@9.15.0",
  "scripts": {
    "lint": "biome check .",
    "format": "biome format --write .",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "test:conformance": "vitest run conformance",
    "test:wasm": "wasm-pack test --node && wasm-pack test --headless --chrome",
    "knip": "knip",
    "attw": "attw --pack",
    "publint": "publint"
  }
}
```

### `.github/workflows/ci.yml` (shape — pin every `uses:` to a SHA)

```yaml
name: ci
on: { pull_request: {}, push: { branches: [main] } }
permissions: { contents: read }
jobs:
  rust:
    strategy: { matrix: { os: [ubuntu-latest, macos-latest], rust: [stable, "1.96.0"] } }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: step-security/harden-runner@<sha>            # egress audit
        with: { egress-policy: audit }
      - uses: actions/checkout@<sha>
      - uses: dtolnay/rust-toolchain@<sha>
        with: { toolchain: ${{ matrix.rust }}, components: "rustfmt, clippy" }
      - uses: Swatinem/rust-cache@<sha>
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets --all-features -- -D warnings
      - run: cargo nextest run --all-features --locked
      - run: cargo deny check
      - run: cargo audit
  conformance:                                              # THE load-bearing gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: cargo nextest run -p thoughtmark-core --test conformance --locked
      - run: pnpm install --frozen-lockfile && pnpm --filter @thoughtmark/core test:conformance
  ts-wasm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: corepack enable && pnpm install --frozen-lockfile
      - run: pnpm typecheck && pnpm lint
      - run: pnpm test:wasm
      - run: pnpm publint && pnpm attw
  actions-hardening:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: zizmor .github/workflows && actionlint
```
> *Mirror of the Claude Code hooks + local `just ci`. A `release.yml` adds `release-plz`, SBOM generation,
> GitHub Artifact Attestations, and OIDC trusted publishing (crates.io + npm `--provenance`); a `scorecard.yml`
> runs OpenSSF Scorecard. CodeQL and OSV-Scanner run as their own scanning workflows.*

### `lefthook.yml` (local gates = CI gates)

```yaml
pre-commit:
  parallel: true
  commands:
    fmt:    { glob: "*.rs",  run: cargo fmt --all -- --check }
    clippy: { run: cargo clippy --all-targets --all-features -- -D warnings }
    typos:  { run: typos }
    biome:  { glob: "*.{ts,tsx,js,json}", run: pnpm biome check {staged_files} }
pre-push:
  commands:
    ci: { run: just ci }
```

### `spec/vectors/` — example vector + layout

```jsonc
// spec/vectors/canon/jcs-0007.json
{
  "vector_id": "jcs-0007",
  "spec_req": "CANON-3",                       // traces to SPEC.md requirement CANON-3
  "canon_version": 1,
  "description": "Object key ordering by UTF-16 code unit; non-ASCII key",
  "input": { "b": 1, "a": 2, "é": 3 },
  "canonical_utf8_hex": "7b2261223a322c2262223a312c22c3a9223a337d",
  "blake3":  "<expected-blake3-hex>",
  "sha256":  "<expected-sha256-hex>",
  "cidv1":   "<expected-cidv1>"
}
```
```
spec/
  SPEC.md            # BCP 14 normative spec, stable requirement IDs
  vectors/
    VERSION          # independent SemVer for the corpus
    CHANGELOG.md     # append-only; changing an expected hash = breaking
    canon/  hash/  cid/  ed25519/  dsse/  merkle/
```

### Other baseline files (contents are short/standard — create at bootstrap)

- **`.editorconfig`**, **`.gitignore`** (incl. `target/`, `node_modules/`, `*.key`, `.env*`, `.claude/settings.local.json`, `CLAUDE.local.md`), **`.gitattributes`** (`* text=auto eol=lf`, `*.wasm binary`).
- **`CODEOWNERS`**, **`SECURITY.md`** (private disclosure + RUSTSEC coordination), **`CONTRIBUTING.md`**.
- **`docs/threat-model.md`** (proves / does-NOT-prove table), **`docs/adr/0001-jcs-crate.md`** (MADR: choose `serde_json_canonicalizer`, reject abandoned `serde_jcs`).
- **`CITATION.cff`**, **`NOTICE`** (Apache-2.0), per-file `// SPDX-License-Identifier: Apache-2.0` headers (lint with `reuse`).
- **`commitlint.config.js`** (Conventional Commits), **`CHANGELOG.md`** (Keep a Changelog).

---

## Bootstrap checklist — every `[MUST]` → the file that satisfies it

| # | `[MUST]` control | File(s) | CI mirror |
|---|------------------|---------|-----------|
| 1 | Agent codebook & invariants | `CLAUDE.md`, `.claude/rules/*` | — |
| 2 | Permissions / sandbox / harness lock-down | `.claude/settings.json`, `managed-settings.json` | — |
| 3 | Blocking + format hooks | `.claude/hooks/guard-bash.sh`, `fmt-lint.sh` | `ci.yml` (same checks) |
| 4 | Pinned toolchain | `rust-toolchain.toml` | matrix in `ci.yml` |
| 5 | Deny-warnings + lints + forbid-unsafe | `Cargo.toml [workspace.lints]` | `clippy -D warnings` |
| 6 | Ban nondeterminism | `clippy.toml` disallowed-methods | clippy job |
| 7 | Dependency policy + audit + provenance | `deny.toml`, `supply-chain/` (cargo-vet) | `cargo deny`/`audit` jobs |
| 8 | Test runner + property tests | nextest + `proptest` (dev-deps) | `nextest` job |
| 9 | Fuzz targets | `fuzz/` (cargo-fuzz) | nightly fuzz job |
| 10 | **Cross-language conformance corpus + gate** | `spec/vectors/**` + runners | **`conformance` job** |
| 11 | No floats in hash path | `clippy::float_arithmetic` (item 5) | clippy job |
| 12 | Strict TS + typecheck | `tsconfig.json` | `tsc --noEmit` job |
| 13 | TS lint/format | `biome.json` (+ Next.js ESLint) | `biome check` job |
| 14 | WASM tests + package correctness | `package.json`, wasm-bindgen-test | `ts-wasm` job |
| 15 | SHA-pinned, hardened Actions | all `.github/workflows/*` | `zizmor`/`actionlint` job |
| 16 | Rulesets: signed commits, required checks, tag protection | repo settings (ruleset) | enforced by GitHub |
| 17 | Local gates == CI | `lefthook.yml`, `justfile` | `just ci` == `ci.yml` |
| 18 | Repo hygiene | `.editorconfig`, `.gitignore`, `.gitattributes`, `CODEOWNERS` | — |
| 19 | Audited crypto + constant-time + key hygiene | crate choices + `subtle`/`zeroize`/`secrecy` | clippy/tests |
| 20 | Authoritative vectors | `spec/vectors/{ed25519,dsse,merkle,…}` (Wycheproof/RFC) | `conformance` job |
| 21 | Secret scanning | `gitleaks` + GitHub push protection | `gitleaks` job |
| 22 | Threat model | `docs/threat-model.md` | review gate |
| 23 | Reproducible builds | `trim-paths`, `Cargo.lock`, pinned `wasm-opt` | rebuild-and-diff job |
| 24 | Normative spec + traceability | `SPEC.md` (BCP 14) | req-ID ↔ vector check |
| 25 | JCS-crate decision recorded | `docs/adr/0001-jcs-crate.md` | — |
| 26 | Licensing compliance | SPDX headers + `NOTICE` + `reuse` | `reuse lint` job |
| 27 | Disclosure + contribution policy | `SECURITY.md`, `CONTRIBUTING.md` | — |

---

## Appendix A — Currency corrections folded into this document (verified June 2026)

1. **Claude permissions** are **deny → ask → allow** (ordered, first-match; deny-at-any-scope wins) — *not* a
   two-way "deny beats allow" merge. There is an `ask` list. Don't cite fabricated version gates.
2. **`PreToolUse`** is the true blocking gate; **`PostToolUse`** runs after the tool and only surfaces stderr.
   The per-handler `if` lives on the **hook handler**, not the matcher.
3. **Subagent** frontmatter uses **`tools:`** (a list), not `allowedTools`; pin `model: opus`.
4. **Skill** frontmatter uses **`disable-model-invocation` / `user-invocable`**, not `invokeOn`/`invokeLimit`;
   custom `commands/*.md` are legacy (merged into skills).
5. **Rust stable is 1.96.0** (2026-05-28), edition 2024; nightly-only tools use a separate dated nightly.
6. **Reproducible builds** use Cargo **`trim-paths`** (RFC 3127, stable since 1.81), not raw
   `--remap-path-prefix`; **pin `wasm-opt`/binaryen** (output not stable across versions).
7. **`next lint` is removed in Next.js 16** — run ESLint/Biome directly.
8. **`serde_jcs` is abandoned** with RFC 8785 divergences → use **`serde_json_canonicalizer`** (record in ADR).
9. **OpenTimestamps has no turn-key Rust library** (`rust-opentimestamps` 0.7.2 parses only); RFC 3161 via
   **`x509-tsp`** — anchoring is an implementation-risk gap, not a drop-in dependency.
10. **`cargo-vet`** is preferred over `cargo-crev` for audit enforcement; **`cargo-nextest`** is the standard test
    runner; `cargo-deny` and `cargo-vet` are complementary.

---

*This document is the quality contract. The single most important control is item 10 in the bootstrap checklist —
the committed cross-language conformance corpus and its CI gate — wired before implementation begins. The single
most important principle is that every gate exists in both a local/agent layer and an authoritative CI layer.*
<!-- REUSE-IgnoreEnd -->
