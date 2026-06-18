// SPDX-License-Identifier: Apache-2.0
// The INDEPENDENT pure-TS oracle (executor D). It calls neither the WASM core nor runOp; it re-derives every
// expected value from a second, independently-authored implementation — `cyberphone/canonicalize` (RFC 8785,
// UTF-16 key sort), `@noble/hashes`, and `multiformats` — and asserts equality against the committed expected
// files. This is the serde_jcs-killer guard: if the oracle disagrees with the Rust-blessed bytes (most likely on
// the astral-plane UTF-16 sort), that is a real bug to INVESTIGATE, never to paper over by re-blessing.
//
// Filename contains "conformance" so it runs under the existing `vitest run conformance` script with no CI edit.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { blake3 } from "@noble/hashes/blake3";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
import canonicalizeImport from "canonicalize";
import { base32 } from "multiformats/bases/base32";
import { CID } from "multiformats/cid";
import * as raw from "multiformats/codecs/raw";
import { create as createMultihash } from "multiformats/hashes/digest";
import { describe, expect, it } from "vitest";

// `canonicalize` is a CJS default-export function; under nodenext + verbatimModuleSyntax tsc types the binding as
// the module namespace, so re-type it to its true call signature (runtime is the function).
const canonicalize = canonicalizeImport as unknown as (input: unknown) => string | undefined;

const BLAKE3_MULTIHASH_CODE = 0x1e;
const I_JSON_MAX = 9_007_199_254_740_991n; // 2^53 - 1
const enc = new TextEncoder();
const TURN_PREFIX = enc.encode("tm-jcs-1:blake3:thoughtmark.turn:");
const OBJECT_PREFIX = enc.encode("tm-jcs-1:blake3:thoughtmark.object:");
const MANIFEST_PREFIX = enc.encode("tm-jcs-1:blake3:thoughtmark.manifest:");
// trail_root hashes the OBJECT domain with BOTH algorithms; SHA-256 uses its own alg-tagged prefix.
const OBJECT_PREFIX_SHA256 = enc.encode("tm-jcs-1:sha256:thoughtmark.object:");

interface Case {
  id: string;
  spec_req: string;
  op: string;
  input: string;
  expected?: string;
  expect_error?: string;
}

interface Manifest {
  cases: Case[];
}

function vectorsDir(): string {
  const fromEnv = process.env["THOUGHTMARK_VECTORS"];
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  return fileURLToPath(new URL("../../../spec/vectors", import.meta.url));
}

function read(root: string, rel: string): Buffer {
  return readFileSync(join(root, rel));
}

/** A rejection carrying the SCREAMING_SNAKE_CASE ErrorCode the core would emit. */
class CanonReject extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

// A strict, dependency-free recursive-descent JSON parser. Unlike `JSON.parse` it (a) detects duplicate keys, (b)
// preserves big integers and rejects those outside the I-JSON safe range, and (c) rejects floats/exponents — so
// the oracle fails closed at the SAME logical stage and with the SAME ErrorCode as the Rust core.
class StrictParser {
  private readonly s: string;
  private i = 0;

  constructor(s: string) {
    this.s = s;
  }

  parse(): unknown {
    this.ws();
    const value = this.value();
    this.ws();
    if (this.i !== this.s.length) {
      throw new CanonReject("CANON_INVALID_JSON");
    }
    return value;
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") {
        break;
      }
      this.i++;
    }
  }

  private value(): unknown {
    const c = this.s[this.i];
    if (c === "{") return this.object();
    if (c === "[") return this.array();
    if (c === '"') return this.string();
    if (c === "t" || c === "f") return this.literalBool();
    if (c === "n") return this.literalNull();
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return this.number();
    // NaN / Infinity / anything else is not valid JSON.
    throw new CanonReject("CANON_INVALID_JSON");
  }

  private object(): Record<string, unknown> {
    this.i++; // {
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') throw new CanonReject("CANON_INVALID_JSON");
      const key = this.string();
      if (seen.has(key)) throw new CanonReject("CANON_INVALID_JSON"); // duplicate key
      seen.add(key);
      this.ws();
      if (this.s[this.i] !== ":") throw new CanonReject("CANON_INVALID_JSON");
      this.i++;
      this.ws();
      out[key] = this.value();
      this.ws();
      const sep = this.s[this.i];
      if (sep === ",") {
        this.i++;
      } else if (sep === "}") {
        this.i++;
        return out;
      } else {
        throw new CanonReject("CANON_INVALID_JSON");
      }
    }
  }

  private array(): unknown[] {
    this.i++; // [
    const out: unknown[] = [];
    this.ws();
    if (this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      this.ws();
      const sep = this.s[this.i];
      if (sep === ",") {
        this.i++;
      } else if (sep === "]") {
        this.i++;
        return out;
      } else {
        throw new CanonReject("CANON_INVALID_JSON");
      }
    }
  }

  // Slice out the full string token (honoring escapes) and let JSON.parse unescape it; advance past it.
  private string(): string {
    const start = this.i;
    let j = this.i + 1; // past opening quote
    while (j < this.s.length) {
      const ch = this.s[j];
      if (ch === "\\") {
        j += 2;
      } else if (ch === '"') {
        const token = this.s.slice(start, j + 1);
        this.i = j + 1;
        return JSON.parse(token) as string;
      } else {
        j++;
      }
    }
    throw new CanonReject("CANON_INVALID_JSON");
  }

  private literalBool(): boolean {
    if (this.s.startsWith("true", this.i)) {
      this.i += 4;
      return true;
    }
    if (this.s.startsWith("false", this.i)) {
      this.i += 5;
      return false;
    }
    throw new CanonReject("CANON_INVALID_JSON");
  }

  private literalNull(): null {
    if (this.s.startsWith("null", this.i)) {
      this.i += 4;
      return null;
    }
    throw new CanonReject("CANON_INVALID_JSON");
  }

  private number(): number {
    const start = this.i;
    if (this.s[this.i] === "-") this.i++;
    while (this.i < this.s.length) {
      const d = this.s[this.i];
      if (d === undefined || d < "0" || d > "9") break;
      this.i++;
    }
    const token = this.s.slice(start, this.i);
    const next = this.s[this.i];
    if (next === "." || next === "e" || next === "E") {
      throw new CanonReject("CANON_NON_DETERMINISTIC_FLOAT");
    }
    if (token === "" || token === "-") throw new CanonReject("CANON_INVALID_JSON");
    const big = BigInt(token);
    if (big > I_JSON_MAX || big < -I_JSON_MAX) {
      throw new CanonReject("CANON_INTEGER_OUT_OF_RANGE");
    }
    return Number(big);
  }
}

function canonicalizeOracle(input: Buffer): Uint8Array {
  const value = new StrictParser(input.toString("utf8")).parse();
  const text = canonicalize(value);
  if (typeof text !== "string") {
    throw new CanonReject("CANON_INVALID_JSON");
  }
  return enc.encode(text);
}

// --- Independent RFC 6962 / RFC 9162 reimplementation (uses only @noble/hashes, never the Rust core) ----------

function hashLeaf(record: Uint8Array): Uint8Array {
  return sha256(concatBytes(new Uint8Array([0x00]), record));
}

function hashChildren(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

function merkleTreeHash(leaves: Uint8Array[]): Uint8Array {
  const stack: Array<[Uint8Array, number]> = [];
  for (const leaf of leaves) {
    let node = leaf;
    let size = 1;
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (top === undefined || top[1] !== size) break;
      stack.pop();
      node = hashChildren(top[0], node);
      size *= 2;
    }
    stack.push([node, size]);
  }
  if (stack.length === 0) return sha256(new Uint8Array(0));
  let root = stack[stack.length - 1]?.[0] as Uint8Array;
  for (let i = stack.length - 2; i >= 0; i--) {
    root = hashChildren(stack[i]?.[0] as Uint8Array, root);
  }
  return root;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function isPow2(n: bigint): boolean {
  return n > 0n && (n & (n - 1n)) === 0n;
}

/** RFC 9162 §2.1.3.2 inclusion verification. */
function verifyInclusion(
  leafHash: Uint8Array,
  leafIndex: bigint,
  treeSize: bigint,
  path: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1n;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = hashChildren(p, r);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = hashChildren(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && bytesEqual(r, root);
}

/** RFC 9162 §2.1.4.2 consistency verification (dual-recompute of both roots). */
function verifyConsistency(
  first: bigint,
  second: bigint,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  path: Uint8Array[],
): boolean {
  if (first > second) return false;
  if (first === 0n) return path.length === 0;
  if (first === second) return path.length === 0 && bytesEqual(oldRoot, newRoot);
  const nodes: Uint8Array[] = [];
  if (isPow2(first)) nodes.push(oldRoot);
  nodes.push(...path);
  const firstNode = nodes[0];
  if (firstNode === undefined) return false;
  let fn = first - 1n;
  let sn = second - 1n;
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = firstNode;
  let sr = firstNode;
  for (let i = 1; i < nodes.length; i++) {
    const c = nodes[i] as Uint8Array;
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = hashChildren(c, fr);
      sr = hashChildren(c, sr);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      sr = hashChildren(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return fn === 0n && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot);
}

const OK_ENVELOPE = '{"ok":true}';
const fromB64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));

/** Run an op via the oracle, returning the output bytes. Canonicalize-class ops throw `CanonReject` on failure;
 *  the verify ops encode failure in their returned envelope (matching the Rust core's `run_op`). */
function oracleRun(c: Case, input: Buffer): Uint8Array {
  switch (c.op) {
    case "canonicalize":
      return canonicalizeOracle(input);
    case "hash_blake3":
      return enc.encode(bytesToHex(blake3(canonicalizeOracle(input))));
    case "hash_sha256":
      return enc.encode(bytesToHex(sha256(canonicalizeOracle(input))));
    case "hash_domain_turn":
    case "hash_domain_object":
    case "hash_domain_manifest": {
      const prefix =
        c.op === "hash_domain_turn"
          ? TURN_PREFIX
          : c.op === "hash_domain_object"
            ? OBJECT_PREFIX
            : MANIFEST_PREFIX;
      return enc.encode(bytesToHex(blake3(concatBytes(prefix, canonicalizeOracle(input)))));
    }
    case "cid_v1": {
      const digest = createMultihash(BLAKE3_MULTIHASH_CODE, blake3(new Uint8Array(input)));
      return enc.encode(CID.create(1, raw.code, digest).toString(base32));
    }
    case "trail_root": {
      const canon = canonicalizeOracle(input);
      const b3 = bytesToHex(blake3(concatBytes(OBJECT_PREFIX, canon)));
      const s2 = bytesToHex(sha256(concatBytes(OBJECT_PREFIX_SHA256, canon)));
      return enc.encode(`{"blake3":"${b3}","sha256":"${s2}"}`);
    }
    case "merkle_root": {
      const req = JSON.parse(input.toString("utf8")) as { leaves: string[] };
      return enc.encode(
        Buffer.from(merkleTreeHash(req.leaves.map((b) => hashLeaf(fromB64(b))))).toString("base64"),
      );
    }
    case "merkle_verify_inclusion": {
      const req = JSON.parse(input.toString("utf8")) as {
        leaf: string;
        proof: { leaf_index: string; tree_size: string; path: string[] };
        root: string;
      };
      const ok = verifyInclusion(
        hashLeaf(fromB64(req.leaf)),
        BigInt(req.proof.leaf_index),
        BigInt(req.proof.tree_size),
        req.proof.path.map(fromB64),
        fromB64(req.root),
      );
      return enc.encode(ok ? OK_ENVELOPE : '{"ok":false,"error":{"code":"MERKLE_PROOF_INVALID"}}');
    }
    case "merkle_verify_consistency": {
      const req = JSON.parse(input.toString("utf8")) as {
        proof: { first: string; second: string; path: string[] };
        old_root: string;
        new_root: string;
      };
      const ok = verifyConsistency(
        BigInt(req.proof.first),
        BigInt(req.proof.second),
        fromB64(req.old_root),
        fromB64(req.new_root),
        req.proof.path.map(fromB64),
      );
      return enc.encode(
        ok ? OK_ENVELOPE : '{"ok":false,"error":{"code":"CONSISTENCY_PROOF_INVALID"}}',
      );
    }
    default:
      throw new Error(`${c.id}: oracle does not know op ${c.op}`);
  }
}

/** The ErrorCode embedded in an `{"ok":false,...}` envelope, or undefined. */
function envelopeCode(out: Uint8Array): string | undefined {
  try {
    const v = JSON.parse(Buffer.from(out).toString("utf8")) as {
      ok?: unknown;
      error?: { code?: unknown };
    };
    if (v.ok === false && typeof v.error?.code === "string") return v.error.code;
  } catch {
    return undefined;
  }
  return undefined;
}

describe("independent pure-TS oracle (cyberphone + noble + multiformats)", () => {
  it("reproduces every vector byte-for-byte (canon/hash/cid/schema/merkle/negative)", () => {
    const root = vectorsDir();
    const manifest = JSON.parse(read(root, "manifest.json").toString("utf8")) as Manifest;
    expect(manifest.cases.length).toBeGreaterThan(0);

    for (const c of manifest.cases) {
      const input = read(root, c.input);
      let output: Uint8Array | undefined;
      let thrown: string | undefined;
      try {
        output = oracleRun(c, input);
      } catch (e) {
        thrown = e instanceof CanonReject ? e.code : `THREW:${String(e)}`;
      }

      if (typeof c.expect_error === "string") {
        const code = thrown ?? (output ? envelopeCode(output) : undefined);
        expect(code, `${c.id}: oracle error code`).toBe(c.expect_error);
        continue;
      }

      if (thrown !== undefined) {
        throw new Error(`${c.id}: oracle threw unexpectedly: ${thrown}`);
      }
      const expectedPath = c.expected;
      if (expectedPath === undefined) {
        throw new Error(`${c.id}: positive case missing expected path`);
      }
      expect(
        output !== undefined && Buffer.from(output).equals(read(root, expectedPath)),
        c.id,
      ).toBe(true);
    }
  });
});
