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

describe("independent pure-TS oracle (cyberphone + noble + multiformats)", () => {
  it("reproduces every canon/hash/cid/negative vector byte-for-byte", () => {
    const root = vectorsDir();
    const manifest = JSON.parse(read(root, "manifest.json").toString("utf8")) as Manifest;
    expect(manifest.cases.length).toBeGreaterThan(0);

    for (const c of manifest.cases) {
      const input = read(root, c.input);

      if (typeof c.expect_error === "string") {
        let code: string | undefined;
        try {
          canonicalizeOracle(input);
        } catch (e) {
          code = e instanceof CanonReject ? e.code : "UNEXPECTED";
        }
        expect(code, `${c.id}: oracle error code`).toBe(c.expect_error);
        continue;
      }

      const expectedPath = c.expected;
      if (expectedPath === undefined) {
        throw new Error(`${c.id}: positive case missing expected path`);
      }
      const expected = read(root, expectedPath).toString("ascii");

      if (c.op === "canonicalize") {
        const out = canonicalizeOracle(input);
        expect(Buffer.from(out).equals(read(root, expectedPath)), c.id).toBe(true);
      } else if (c.op === "hash_blake3") {
        expect(bytesToHex(blake3(canonicalizeOracle(input))), c.id).toBe(expected);
      } else if (c.op === "hash_sha256") {
        expect(bytesToHex(sha256(canonicalizeOracle(input))), c.id).toBe(expected);
      } else if (c.op === "hash_domain_turn") {
        const preimage = concatBytes(TURN_PREFIX, canonicalizeOracle(input));
        expect(bytesToHex(blake3(preimage)), c.id).toBe(expected);
      } else if (c.op === "cid_v1") {
        const digest = createMultihash(BLAKE3_MULTIHASH_CODE, blake3(new Uint8Array(input)));
        const cid = CID.create(1, raw.code, digest);
        expect(cid.toString(base32), c.id).toBe(expected);
      } else {
        throw new Error(`${c.id}: oracle does not know op ${c.op}`);
      }
    }
  });
});
