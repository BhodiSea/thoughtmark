<!-- SPDX-License-Identifier: Apache-2.0 -->
# thoughtmark-vectors

The thoughtmark conformance corpus (`spec/vectors/`) as a versioned crate — the **Corpus-SemVer** train
(architecture §16). The corpus is the language-neutral oracle for byte-identity (I1); embedding it as a crate lets
downstream code take a versioned **dev-dependency** on it, so a MAJOR corpus release (any changed expected byte)
forces an explicit, reviewed bump in both engines rather than a silent re-bless.

Exposes the corpus manifest + version as `pub const`s. The byte files live at the repo root (`spec/vectors/`), the
single source of truth.

> Publishing note: the published `.crate` must vendor the corpus bytes (the embedded paths reach outside the crate
> directory). In-workspace builds resolve them directly. See `docs/phase-3-release-checklist.md`.

License: Apache-2.0.
