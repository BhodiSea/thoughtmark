// SPDX-License-Identifier: Apache-2.0
// Typed-facade tests (§14.6): the ergonomic verbs over the `run_op` airlock. Drives the typed `verify` over the
// blessed all-pass fixture and asserts the wire→typed mapping (bigint times, camelCase, populated lineage), plus
// the canonicalize/hash verbs and the malformed-input throw.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { canonicalize, ensureReady, hash, ThoughtmarkError, verify } from "../src/node.js";
import type { Policy } from "../src/types.js";

interface WirePolicy {
  accepted_canon_versions: ["tm-jcs-1"];
  max_clock_skew_ms: string;
  require_anchor: boolean;
  required_witnesses: number;
  trusted_keys: string[];
  trusted_log_keys: string[];
  required_actions?: string[];
}
interface Fixture {
  bundle: unknown;
  policy: WirePolicy;
  env: { now_unix_ms: string };
}

function loadFixture(name: string): Fixture {
  const url = new URL(`../../../spec/vectors/verify/${name}/input.json`, import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), "utf8")) as Fixture;
}

function typedPolicy(w: WirePolicy): Policy {
  return {
    acceptedCanonVersions: w.accepted_canon_versions,
    maxClockSkewMs: BigInt(w.max_clock_skew_ms),
    requireAnchor: w.require_anchor,
    requiredWitnesses: w.required_witnesses,
    trustedKeys: w.trusted_keys,
    trustedLogKeys: w.trusted_log_keys,
    ...(w.required_actions !== undefined ? { requiredActions: w.required_actions } : {}),
  };
}

describe("typed facade (@thoughtmark/core §14.6)", () => {
  beforeAll(async () => {
    await ensureReady();
  });

  it("verify() maps the all-pass result to the typed shape", () => {
    const f = loadFixture("0001");
    const r = verify(f.bundle, typedPolicy(f.policy), BigInt(f.env.now_unix_ms));
    expect(r.total).toBe(true);
    expect(r.verifiedAt).toBe(BigInt(f.env.now_unix_ms));
    expect(r.checks).toHaveLength(9);
    expect(r.established.unalteredSinceCapture).toBe(true);
    expect(r.established.lineage).toHaveLength(2);
    expect(r.established.lineage?.[0]?.action).toBe("create");
    expect(r.established.lineage?.[1]?.participantKind).toBe("human");
    expect(r.notEstablished.validityOfRecord).toContain("Not proven");
  });

  it("verify() returns total:false for a tamper (never throws)", () => {
    const f = loadFixture("0002");
    const r = verify(f.bundle, typedPolicy(f.policy), BigInt(f.env.now_unix_ms));
    expect(r.total).toBe(false);
    expect(r.established.unalteredSinceCapture).toBe(false);
    const dsse = r.checks.find((c) => c.kind === "DsseSignature");
    expect(dsse?.status).toBe("Fail");
    expect(dsse?.code).toBe("SIG_INVALID");
  });

  it("canonicalize() sorts object keys (RFC 8785)", () => {
    const out = new TextDecoder().decode(canonicalize({ b: 1, a: 2 }));
    expect(out).toBe('{"a":2,"b":1}');
  });

  it("hash() returns a tagged 32-byte digest", () => {
    const d = hash({ a: 1 }, "blake3");
    expect(d.alg).toBe("blake3");
    expect(d.bytes).toHaveLength(32);
  });

  it("a malformed value throws a ThoughtmarkError with a stable code", () => {
    expect(() => canonicalize({ x: 1.5 })).toThrow(ThoughtmarkError);
    try {
      canonicalize({ x: 1.5 });
    } catch (e) {
      expect((e as ThoughtmarkError).code).toBe("CANON_NON_DETERMINISTIC_FLOAT");
    }
  });
});
