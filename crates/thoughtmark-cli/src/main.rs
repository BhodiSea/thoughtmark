// SPDX-License-Identifier: Apache-2.0
//! `tm` — the thoughtmark reference/debug CLI (Phase 0 stub).
//!
//! Phase 0 prints the canonical output of a named op (today, always the `NOT_IMPLEMENTED` envelope) and exits
//! non-zero. The `verify`/`print`/`bless` subcommands land alongside Tier-0 logic.

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let op = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "verify".to_owned());
    let bytes = thoughtmark_core::ops::run_op(&op, &[]);
    if std::io::stdout().write_all(&bytes).is_err() {
        return ExitCode::from(74); // EX_IOERR
    }
    let _ = std::io::stdout().write_all(b"\n");
    // Phase 0: nothing is implemented yet, so signal "not established".
    ExitCode::from(2)
}
