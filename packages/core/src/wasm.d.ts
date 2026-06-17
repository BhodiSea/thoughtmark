// SPDX-License-Identifier: Apache-2.0
// Ambient type for the wasm-pack `--target web` artifact (generated into ../wasm/, gitignored, rebuilt in CI).
// This lets `tsc`, the build, `publint`, and `attw` run without the artifact present; the real artifact (and its
// generated .d.ts, which takes precedence when present) is loaded at runtime by the Node/browser facades.
declare module "*thoughtmark_wasm.js" {
  export interface InitOpts {
    module_or_path: BufferSource;
  }
  export default function init(opts?: InitOpts | BufferSource | URL): Promise<unknown>;
  export function run_op(op: string, input: Uint8Array): Uint8Array;
  export function canon_version(): number;
}
