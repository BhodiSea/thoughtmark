// SPDX-License-Identifier: Apache-2.0
// Node loader for the thoughtmark WASM core.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import init, { canon_version, run_op } from "../wasm/thoughtmark_wasm.js";

// The runtime-agnostic typed verbs (§14.6) — re-exported so the Node entry carries the full surface.
export * from "./api.js";

let ready: Promise<void> | undefined;

/**
 * Instantiate the WASM module once, injecting its bytes from disk so the single `--target web` artifact also
 * serves Node (no `fetch`). Must be awaited before {@link runOp} / {@link canonVersion}.
 */
export function ensureReady(): Promise<void> {
  ready ??= (async (): Promise<void> => {
    const wasmUrl = new URL("../wasm/thoughtmark_wasm_bg.wasm", import.meta.url);
    const bytes = readFileSync(fileURLToPath(wasmUrl));
    await init({ module_or_path: bytes });
  })();
  return ready;
}

/** Run a named operation, returning canonical output bytes (byte-identical to the native Rust core, I1). */
export function runOp(op: string, input: Uint8Array): Uint8Array {
  return run_op(op, input);
}

/** The canonicalization format identifier reported by the WASM core (e.g. `"tm-jcs-1"`). */
export function canonVersion(): string {
  return canon_version();
}
