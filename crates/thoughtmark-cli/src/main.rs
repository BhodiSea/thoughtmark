// SPDX-License-Identifier: Apache-2.0
//! `tm` — the thoughtmark reference/debug CLI.
//!
//! Phase 1 ships `tm bless`: it regenerates (or, with `--check`, verifies) the `spec/vectors/` expected files from
//! the native Rust core, driving the SAME `thoughtmark_core::ops::run_op` the conformance test uses — so blessed
//! bytes can never drift from the oracle. Blessing is deliberate: a changed expected byte is a BREAKING corpus
//! release (bump `spec/vectors/VERSION` + `CHANGELOG.md`). `print`/`verify` subcommands land in later phases.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("tm: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some("bless") => {
            let mut check = false;
            let mut dir: Option<&str> = None;
            for arg in args.iter().skip(2) {
                if arg == "--check" {
                    check = true;
                } else {
                    dir = Some(arg);
                }
            }
            bless(&PathBuf::from(dir.unwrap_or("spec/vectors")), check)
        }
        Some("bundle-check") => {
            let file = args.get(2).ok_or("usage: tm bundle-check FILE")?;
            bundle_check(&PathBuf::from(file))
        }
        Some("verify") => {
            // The full cryptographic verify() pipeline is a later phase; bundle-check is the Phase-2 stand-in.
            Err("tm verify: not implemented (Phase 3). Use `tm bundle-check FILE` for the structural check.".into())
        }
        _ => Err("usage: tm bless [--check] [DIR] | tm bundle-check FILE".into()),
    }
}

/// Structurally validate a `ThoughtmarkBundle` JSON file via the core `bundle_check` op (media type / version /
/// canon version). NOT the full cryptographic `verify()` — that is a later phase.
fn bundle_check(file: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(file)?;
    let out = thoughtmark_core::ops::run_op("bundle_check", &bytes);
    match extract_code(&out) {
        None => {
            println!(
                "{}: structurally valid (media type / version / canon version ok).",
                file.display()
            );
            Ok(())
        }
        Some(code) => Err(format!("{}: bundle invalid ({code})", file.display()).into()),
    }
}

fn str_field(value: &serde_json::Value, key: &str) -> Result<String, Box<dyn Error>> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("manifest case missing string field `{key}`").into())
}

/// Parse `{"ok":false,"error":{"code":"..."}}` → the code token.
fn extract_code(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("ok")?.as_bool()? {
        return None;
    }
    value.get("error")?.get("code")?.as_str().map(str::to_owned)
}

fn write_or_check(
    path: &Path,
    content: &[u8],
    check: bool,
    id: &str,
    mismatches: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    if check {
        let existing = fs::read(path).unwrap_or_default();
        if existing != content {
            mismatches.push(format!("{id}: {}", path.display()));
        }
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
    }
    Ok(())
}

fn bless(root: &Path, check: bool) -> Result<(), Box<dyn Error>> {
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("manifest.json"))?)?;
    let cases = manifest
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("manifest.json: missing `cases` array")?;

    let declared = manifest
        .get("vector_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or("manifest.json: missing `vector_count`")?;
    if usize::try_from(declared)? != cases.len() {
        return Err(format!(
            "manifest.json: vector_count {declared} != {} cases declared",
            cases.len()
        )
        .into());
    }

    let mut mismatches = Vec::new();
    for case in cases {
        let id = str_field(case, "id")?;
        let op = str_field(case, "op")?;
        let input = fs::read(root.join(str_field(case, "input")?))?;
        let output = thoughtmark_core::ops::run_op(&op, &input);

        if let Some(expect_error) = case.get("expect_error").and_then(serde_json::Value::as_str) {
            let code = extract_code(&output)
                .ok_or_else(|| format!("{id}: expected an error envelope from run_op"))?;
            if code != expect_error {
                return Err(format!(
                    "{id}: run_op produced `{code}` but manifest expect_error=`{expect_error}` (investigate — do not re-bless around a real divergence)"
                )
                .into());
            }
            let path = root.join(str_field(case, "expected_code")?);
            write_or_check(&path, code.as_bytes(), check, &id, &mut mismatches)?;
        } else {
            let path = root.join(str_field(case, "expected")?);
            write_or_check(&path, &output, check, &id, &mut mismatches)?;
        }
    }

    if check {
        if mismatches.is_empty() {
            println!(
                "bless --check: all {} cases match the native Rust oracle.",
                cases.len()
            );
            Ok(())
        } else {
            Err(format!(
                "corpus is STALE (re-run `just bless` and review the diff):\n  {}",
                mismatches.join("\n  ")
            )
            .into())
        }
    } else {
        println!(
            "blessed {} cases from the native Rust core. REVIEW the diff: any changed expected byte is a BREAKING corpus release (bump spec/vectors/VERSION + CHANGELOG.md).",
            cases.len()
        );
        Ok(())
    }
}
