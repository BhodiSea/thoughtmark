// SPDX-License-Identifier: Apache-2.0
// Browser loader for the thoughtmark WASM core (the headless-browser conformance leg, run in CI).
import init, { canon_version, run_op } from "../wasm/thoughtmark_wasm.js";

// The runtime-agnostic typed verbs (§14.6) — re-exported so the browser entry carries the full surface.
export * from "./api.js";

let ready: Promise<void> | undefined;

/** Instantiate the WASM module once via streaming fetch of the colocated `.wasm`. */
export function ensureReady(): Promise<void> {
  ready ??= init(new URL("../wasm/thoughtmark_wasm_bg.wasm", import.meta.url)).then(
    () => undefined,
  );
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
