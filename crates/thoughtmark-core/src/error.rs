// SPDX-License-Identifier: Apache-2.0
//! Stable, content-free error model.
//!
//! Error *codes* are part of the conformance contract: their wire strings ([`ErrorCode::as_str`]) appear in the
//! canonical envelope and MUST NOT change once shipped (changing one is a breaking spec change). The error type
//! carries no record content (I5/I7).

use core::fmt;

/// A stable, content-free error code.
///
/// Variants are append-only. The string form of each code is normative (it appears in the conformance envelope),
/// so renaming or repurposing a code is a breaking spec change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The operation is not yet implemented (the Phase 0 stub state).
    NotImplemented,
    /// An internal invariant was violated. Carries a `'static`, content-free reason instead of panicking — a
    /// Rust panic crossing the WASM boundary becomes an uncatchable `RuntimeError` (arch §2.3).
    Internal(&'static str),
}

impl ErrorCode {
    /// The stable wire string for this code, as used in the conformance envelope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotImplemented => "NOT_IMPLEMENTED",
            ErrorCode::Internal(_) => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The library error type. Content-free by construction (I5/I7).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// The stable error code.
    pub code: ErrorCode,
}

impl Error {
    /// Construct an error from a [`ErrorCode`].
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    /// The not-implemented error (the Phase 0 stub state).
    #[must_use]
    pub const fn not_implemented() -> Self {
        Self::new(ErrorCode::NotImplemented)
    }

    /// An internal-invariant error carrying a `'static`, content-free reason.
    #[must_use]
    pub const fn internal(reason: &'static str) -> Self {
        Self::new(ErrorCode::Internal(reason))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)
    }
}

impl core::error::Error for Error {}
