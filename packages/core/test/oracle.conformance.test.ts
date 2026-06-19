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
import { ed25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import canonicalizeImport from "canonicalize";
import { base32 } from "multiformats/bases/base32";
import { base58btc } from "multiformats/bases/base58";
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
const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const SP = new Uint8Array([0x20]);
const fromB64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
const toB64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
const errEnvelope = (code: string): Uint8Array =>
  enc.encode(`{"ok":false,"error":{"code":"${code}"}}`);

/** PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body — LEN over BYTE length. */
function pae(payloadType: string, body: Uint8Array): Uint8Array {
  const typeBytes = enc.encode(payloadType);
  return concatBytes(
    enc.encode("DSSEv1"),
    SP,
    enc.encode(String(typeBytes.length)),
    SP,
    typeBytes,
    SP,
    enc.encode(String(body.length)),
    SP,
    body,
  );
}

/** Resolve a verification key from a `did:key:z…` or a hex public key (independent of the Rust decoder). */
function resolveKey(key: string): Uint8Array {
  if (key.startsWith("did:key:")) {
    const decoded = base58btc.decode(key.slice("did:key:".length));
    if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Error("bad did:key");
    }
    return decoded.slice(2);
  }
  return hexToBytes(key);
}

const NL = new Uint8Array([0x0a]);
const EM_DASH_SP = new Uint8Array([0xe2, 0x80, 0x94, 0x20]);

function startsWith(arr: Uint8Array, prefix: Uint8Array): boolean {
  if (arr.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (arr[i] !== prefix[i]) return false;
  return true;
}

function splitBytes(arr: Uint8Array, sep: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i < arr.length; i++) {
    if (arr[i] === sep) {
      out.push(arr.subarray(start, i));
      start = i + 1;
    }
  }
  out.push(arr.subarray(start));
  return out;
}

/** Split a C2SP signed note into [signed text, signature block] at the mandatory blank-line separator (a lone
 *  `\n`): text ends in a newline, then a blank line, then ≥1 signature line. The signed text includes its final
 *  newline but not the blank line. Returns null (→ fail closed) if there is no blank-line separator. */
function splitNote(note: Uint8Array): [Uint8Array, Uint8Array] | null {
  for (let i = 0; i + 1 < note.length; i++) {
    if (note[i] === 0x0a && note[i + 1] === 0x0a) {
      return [note.subarray(0, i + 1), note.subarray(i + 2)];
    }
  }
  return null;
}

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
    case "dsse_pae": {
      const req = JSON.parse(input.toString("utf8")) as { payload_type: string; body_b64: string };
      return pae(req.payload_type, fromB64(req.body_b64));
    }
    case "ed25519_verify": {
      const req = JSON.parse(input.toString("utf8")) as {
        pubkey_hex: string;
        msg_hex: string;
        sig_hex: string;
      };
      // Key problems → SIG_MALFORMED_KEY; signature problems → SIG_INVALID (matching the Rust op's mapping).
      let pubkey: Uint8Array;
      try {
        pubkey = hexToBytes(req.pubkey_hex);
        if (pubkey.length !== 32) return errEnvelope("SIG_MALFORMED_KEY");
        ed25519.Point.fromHex(pubkey); // on-curve check
      } catch {
        return errEnvelope("SIG_MALFORMED_KEY");
      }
      let sig: Uint8Array;
      try {
        sig = hexToBytes(req.sig_hex);
      } catch {
        return errEnvelope("SIG_INVALID");
      }
      if (sig.length !== 64) return errEnvelope("SIG_INVALID");
      let ok = false;
      try {
        // zip215:false = RFC 8032 strict (cofactorless), the closest equivalent to dalek's verify_strict.
        ok = ed25519.verify(sig, hexToBytes(req.msg_hex), pubkey, { zip215: false });
      } catch {
        ok = false;
      }
      return ok ? enc.encode(OK_ENVELOPE) : errEnvelope("SIG_INVALID");
    }
    case "did_key_decode": {
      try {
        const pubkey = resolveKey(input.toString("utf8"));
        ed25519.Point.fromHex(pubkey);
        return enc.encode(bytesToHex(pubkey));
      } catch {
        return errEnvelope("SIG_MALFORMED_KEY");
      }
    }
    case "dsse_verify_envelope": {
      const req = JSON.parse(input.toString("utf8")) as {
        envelope: {
          payload: string;
          payloadType: string;
          signatures: Array<{ keyid: string; sig: string }>;
        };
        keys: string[];
      };
      const env = req.envelope;
      if (env.payloadType !== DSSE_PAYLOAD_TYPE) return errEnvelope("DSSE_PAYLOAD_TYPE_MISMATCH");
      const payload = fromB64(env.payload);
      const paeBytes = pae(env.payloadType, payload);
      const keys: Uint8Array[] = [];
      for (const k of req.keys) {
        try {
          keys.push(resolveKey(k));
        } catch {
          return errEnvelope("SIG_MALFORMED_KEY");
        }
      }
      for (const s of env.signatures) {
        const sig = fromB64(s.sig);
        if (sig.length !== 64) continue;
        for (const pk of keys) {
          try {
            if (ed25519.verify(sig, paeBytes, pk, { zip215: false })) return payload;
          } catch {
            /* try the next key */
          }
        }
      }
      return errEnvelope("SIG_INVALID");
    }
    case "sign_statement": {
      const req = JSON.parse(input.toString("utf8")) as {
        seed_hex: string;
        keyid: string;
        statement: unknown;
      };
      const canonStmt = canonicalize(req.statement);
      if (typeof canonStmt !== "string") throw new Error(`${c.id}: statement not canonicalizable`);
      const payload = enc.encode(canonStmt);
      const sig = ed25519.sign(pae(DSSE_PAYLOAD_TYPE, payload), hexToBytes(req.seed_hex));
      const envelope = {
        payload: toB64(payload),
        payloadType: DSSE_PAYLOAD_TYPE,
        signatures: [{ keyid: req.keyid, sig: toB64(sig) }],
      };
      const canonEnv = canonicalize(envelope);
      if (typeof canonEnv !== "string") throw new Error(`${c.id}: envelope not canonicalizable`);
      return enc.encode(canonEnv);
    }
    case "checkpoint_body": {
      const cp = JSON.parse(input.toString("utf8")) as {
        origin: string;
        size: string;
        root: string;
        extensions?: string[];
      };
      const parts: Uint8Array[] = [
        enc.encode(cp.origin),
        NL,
        enc.encode(cp.size),
        NL,
        enc.encode(cp.root),
        NL,
      ];
      for (const ext of cp.extensions ?? []) {
        parts.push(enc.encode(ext), NL);
      }
      return concatBytes(...parts);
    }
    case "checkpoint_verify": {
      const req = JSON.parse(input.toString("utf8")) as {
        note_b64: string;
        keyname: string;
        pubkey_hex: string;
      };
      const note = fromB64(req.note_b64);
      let pubkey: Uint8Array;
      try {
        pubkey = hexToBytes(req.pubkey_hex);
        if (pubkey.length !== 32) return errEnvelope("SIG_MALFORMED_KEY");
        ed25519.Point.fromHex(pubkey);
      } catch {
        return errEnvelope("SIG_MALFORMED_KEY");
      }
      const noteSplit = splitNote(note);
      if (noteSplit === null) return errEnvelope("CHECKPOINT_SIGNATURE_INVALID");
      const [body, sigBlock] = noteSplit;
      const keynameBytes = enc.encode(req.keyname);
      const kh = sha256(concatBytes(keynameBytes, new Uint8Array([0x0a, 0x01]), pubkey)).subarray(
        0,
        4,
      );
      let matched = false;
      for (const line of splitBytes(sigBlock, 0x0a)) {
        if (!startsWith(line, EM_DASH_SP)) continue;
        const after = line.subarray(4);
        const sp = after.indexOf(0x20);
        if (sp < 0) continue;
        if (!bytesEqual(after.subarray(0, sp), keynameBytes)) continue;
        const blob = fromB64(new TextDecoder().decode(after.subarray(sp + 1)));
        if (blob.length !== 68 || !bytesEqual(blob.subarray(0, 4), kh)) continue;
        try {
          if (ed25519.verify(blob.subarray(4), body, pubkey, { zip215: false })) {
            matched = true;
            break;
          }
        } catch {
          /* try next */
        }
      }
      if (!matched) return errEnvelope("CHECKPOINT_SIGNATURE_INVALID");
      const lines = splitBytes(body, 0x0a).map((l) => new TextDecoder().decode(l));
      const exts = lines.slice(3).filter((l) => l.length > 0);
      const base = { origin: lines[0], root: lines[2], size: lines[1] };
      const cp = exts.length > 0 ? { ...base, extensions: exts } : base;
      const canonCp = canonicalize(cp);
      if (typeof canonCp !== "string") throw new Error(`${c.id}: checkpoint not canonicalizable`);
      return enc.encode(canonCp);
    }
    case "bundle_check": {
      const b = JSON.parse(input.toString("utf8")) as {
        media_type?: unknown;
        bundle_version?: unknown;
        canon_version?: unknown;
        envelope?: unknown;
        inclusion?: unknown;
        verification_material?: unknown;
        checkpoint?: unknown;
      };
      // Structural gate (mirrors the Rust op): required fields present, then media-type / version / canon checks.
      if (
        b.envelope === undefined ||
        b.inclusion === undefined ||
        b.verification_material === undefined ||
        b.checkpoint === undefined
      ) {
        return errEnvelope("BUNDLE_SCHEMA_INVALID");
      }
      if (b.media_type !== "application/vnd.thoughtmark.bundle.v1+json") {
        return errEnvelope("BUNDLE_SCHEMA_INVALID");
      }
      if (b.bundle_version !== 1) return errEnvelope("BUNDLE_VERSION_UNSUPPORTED");
      if (b.canon_version !== "tm-jcs-1") return errEnvelope("UNKNOWN_CANON_VERSION");
      return enc.encode(OK_ENVELOPE);
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
