// SPDX-License-Identifier: Apache-2.0
// Cross-language conformance — the WASM-under-Node executor (row 10). Asserts @thoughtmark/core's output is
// byte-identical to every spec/vectors case, against the SAME corpus the native Rust executor reads (R13). Against
// Phase-0 stubs every case is the canonical NOT_IMPLEMENTED envelope — a real byte-equality assertion.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ensureReady, runOp } from "../src/node.js";

interface VectorFile {
  vector_id: string;
  spec_req: string;
  op: string;
  expected_bytes_b64: string;
}

function vectorsDir(): string {
  const fromEnv = process.env["THOUGHTMARK_VECTORS"];
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  return fileURLToPath(new URL("../../../spec/vectors", import.meta.url));
}

function collectJson(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      collectJson(path, out);
    } else if (name.endsWith(".json") && name !== "manifest.json") {
      out.push(path);
    }
  }
}

describe("cross-language conformance (WASM under Node)", () => {
  it("is byte-identical to the spec/vectors corpus", async () => {
    await ensureReady();

    const files: string[] = [];
    collectJson(vectorsDir(), files);
    files.sort();
    expect(files.length, "corpus is empty — the gate would be vacuous").toBeGreaterThan(0);

    for (const file of files) {
      const v = JSON.parse(readFileSync(file, "utf8")) as VectorFile;
      const expected = Buffer.from(v.expected_bytes_b64, "base64");
      // Phase 0 ops ignore input (CORE-2); canonical input wiring lands in Phase 1.
      const actual = Buffer.from(runOp(v.op, new Uint8Array()));
      expect(actual.equals(expected), `vector ${v.vector_id} (spec_req ${v.spec_req})`).toBe(true);
    }
  });
});
