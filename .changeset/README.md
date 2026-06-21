# Changesets

This directory tracks pending version bumps for the npm packages (`@thoughtmark/core`, `@thoughtmark/vectors`),
the Code-SemVer train for the TS engine (arch §16; qf Domain 5). Add a changeset with `pnpm changeset` whenever a
PR changes the public TS surface; CI's `changeset status` gate blocks a surface change with no changeset.

The two packages are **`fixed`** together (see `config.json`), so they always bump as one — the "1.0 trio ships
together" rule, mirrored on the TS side (the Rust `thoughtmark-core` + `thoughtmark-vectors` train is governed by
`release-plz.toml`). Publishing itself is OIDC Trusted Publishing in `.github/workflows/release.yml`, not
`changeset publish` — see `docs/phase-3-release-checklist.md`.
