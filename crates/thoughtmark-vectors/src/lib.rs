// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `thoughtmark-vectors` — the conformance corpus as a versioned crate (arch §16, the Corpus-SemVer train).
//!
//! The `spec/vectors/` corpus is the language-neutral oracle for byte-identity (I1). This crate embeds the
//! corpus manifest + version so downstream crates can take a **versioned dev-dependency** on the corpus: a MAJOR
//! corpus release (any changed expected byte) then forces an explicit, reviewed version bump in both the Rust and
//! TS engines, rather than a silent re-bless. The byte files themselves live at the repo root (`spec/vectors/`),
//! the single source of truth.
//!
//! In-workspace builds resolve the embedded paths directly; the **published** `.crate` must vendor the corpus
//! bytes (a `build.rs` copy or a pre-publish vendoring step), since the embedded paths reach outside the crate
//! directory — see `docs/phase-3-release-checklist.md`.

/// The conformance corpus manifest JSON (`spec/vectors/manifest.json`) — the case index + toolchain pins.
pub const MANIFEST_JSON: &str = include_str!("../../../spec/vectors/manifest.json");

/// The corpus SemVer string (`spec/vectors/VERSION`), trimmed of trailing whitespace by the caller.
pub const VERSION: &str = include_str!("../../../spec/vectors/VERSION");

/// The frozen canonicalization format identifier the corpus was blessed under.
pub const CANON_VERSION: &str = "tm-jcs-1";
