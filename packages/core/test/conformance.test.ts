// SPDX-License-Identifier: Apache-2.0
// Cross-language conformance — the WASM-under-Node executor (row 10). Asserts @thoughtmark/core's output is
// byte-identical to every spec/vectors case, against the SAME corpus the native Rust executor reads (R13). Each
// manifest case maps 1:1 to a runOp(op, input) call: positive cases compare output bytes to the `expected` file;
// negative cases assert the embedded ErrorCode equals `expect_error` (fail-closed).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ensureReady, runOp } from "../src/node.js";

interface Case {
  id: string;
  spec_req: string;
  op: string;
  input: string;
  expected?: string;
  expect_error?: string;
  expected_code?: string;
}

interface Manifest {
  vector_count: number;
  cases: Case[];
}

function vectorsDir(): string {
  const fromEnv = process.env["THOUGHTMARK_VECTORS"];
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  return fileURLToPath(new URL("../../../spec/vectors", import.meta.url));
}

function extractCode(out: Uint8Array): string | undefined {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(out).toString("utf8"));
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      (parsed as { ok?: unknown }).ok === false
    ) {
      const code = (parsed as { error?: { code?: unknown } }).error?.code;
      return typeof code === "string" ? code : undefined;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

describe("cross-language conformance (WASM under Node)", () => {
  it("is byte-identical to the spec/vectors corpus", async () => {
    await ensureReady();

    const root = vectorsDir();
    const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")) as Manifest;

    expect(manifest.cases.length, "corpus is empty — the gate would be vacuous").toBeGreaterThan(0);
    // Count parity with the native Rust executor (R13).
    expect(manifest.cases.length).toBe(manifest.vector_count);

    for (const c of manifest.cases) {
      const input = readFileSync(join(root, c.input));
      const out = runOp(c.op, new Uint8Array(input));
      if (typeof c.expect_error === "string") {
        expect(extractCode(out), `${c.id} (${c.op}): error code`).toBe(c.expect_error);
      } else if (typeof c.expected === "string") {
        const expected = readFileSync(join(root, c.expected));
        expect(Buffer.from(out).equals(expected), `${c.id} (${c.op})`).toBe(true);
      } else {
        throw new Error(`${c.id}: case has neither expected nor expect_error`);
      }
    }
  });
});
