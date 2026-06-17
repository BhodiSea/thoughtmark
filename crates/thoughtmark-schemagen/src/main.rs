// SPDX-License-Identifier: Apache-2.0
//! Build-only: generate JSON Schema + TypeScript types from `thoughtmark-schema` (Phase 0 stub).

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "thoughtmark-schemagen: not implemented (Phase 0 stub). Targets schema v{}.",
        thoughtmark_schema::SCHEMA_VERSION
    );
    ExitCode::from(2)
}
