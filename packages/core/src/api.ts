// SPDX-License-Identifier: Apache-2.0
/**
 * The typed verb facade (arch §14.6), a thin layer over the `run_op` byte-airlock (§12.1). Each verb marshals its
 * input to JSON bytes, calls `run_op`, and decodes the canonical output — byte-identity is enforced at the
 * `runOp` corpus level, so this layer only adds ergonomics (typed in/out), never hash-significant bytes.
 *
 * `init()`/`ensureReady()` (from the runtime entry) MUST be awaited before any verb is called.
 */

import { run_op } from "../wasm/thoughtmark_wasm.js";
import type {
  CanonVersion,
  CheckOutcome,
  Digest,
  ErrorCode,
  Established,
  HashAlg,
  LineageStep,
  NotEstablished,
  Policy,
  VerificationResult,
} from "./types.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** A typed error carrying a stable {@link ErrorCode} (the cross-language error contract). */
export class ThoughtmarkError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode) {
    super(`thoughtmark: ${code}`);
    this.code = code;
    this.name = "ThoughtmarkError";
  }
}

/** The canonical error envelope `{"ok":false,"error":{"code":...}}` code, or `undefined` for a non-envelope. */
function envelopeCode(out: Uint8Array): ErrorCode | undefined {
  // A canonical envelope is short and starts with `{"ok":false`; only then attempt a parse.
  if (out.length === 0 || out[0] !== 0x7b /* { */) return undefined;
  try {
    const v = JSON.parse(dec.decode(out)) as { ok?: unknown; error?: { code?: unknown } };
    if (v.ok === false && typeof v.error?.code === "string") return v.error.code as ErrorCode;
  } catch {
    return undefined;
  }
  return undefined;
}

/** Run an op, throwing a {@link ThoughtmarkError} if it returned an error envelope. */
function runOrThrow(op: string, input: Uint8Array): Uint8Array {
  const out = run_op(op, input);
  const code = envelopeCode(out);
  if (code !== undefined) throw new ThoughtmarkError(code);
  return out;
}

/** Decode 64 lowercase hex characters to 32 raw bytes. */
function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * RFC 8785 JCS canonicalization (§4): the deterministic byte form of `value`. The wasm re-canonicalizes the
 * input, so the JS `JSON.stringify` here is only transport (it never decides the output bytes); a float or an
 * unsupported value fails closed inside the core.
 */
export function canonicalize(value: unknown, _v?: CanonVersion): Uint8Array {
  return runOrThrow("canonicalize", enc.encode(JSON.stringify(value)));
}

/** Canonicalize then hash with `alg` (default BLAKE3), returning a tagged {@link Digest} (§4.4). */
export function hash(value: unknown, alg: HashAlg = "blake3"): Digest {
  const op = alg === "sha256" ? "hash_sha256" : "hash_blake3";
  const out = runOrThrow(op, enc.encode(JSON.stringify(value)));
  return { alg, bytes: fromHex(dec.decode(out)) };
}

// ── verify (§11) ──────────────────────────────────────────────────────────────────────────────────────────────

interface WireDigest {
  alg: HashAlg;
  bytes_hex: string;
}
interface WireCheck {
  kind: CheckOutcome["kind"];
  status: CheckOutcome["status"];
  code?: ErrorCode;
  detail?: { matched?: number; required?: number; tree_size?: string };
}
interface WireLineage {
  participant_kind: "human" | "ai";
  participant_id: string;
  action: string;
  at: string;
}
interface WireEstablished {
  existed_at_or_before?: string;
  unaltered_since_capture: boolean;
  lineage?: WireLineage[];
  bound_subject_digest?: WireDigest;
  signed_by: string[];
  log_origin?: string;
}
interface WireNotEstablished {
  validity_of_record: string;
  faithfulness: string;
  authorship_truth: string;
  completeness: string;
  time_upper_bound_only: string;
}
interface WireResult {
  schema: string;
  verified_at: string;
  total: boolean;
  checks: WireCheck[];
  established: WireEstablished;
  not_established: WireNotEstablished;
}

function mapCheck(c: WireCheck): CheckOutcome {
  const out: CheckOutcome = { kind: c.kind, status: c.status };
  if (c.code !== undefined) out.code = c.code;
  if (c.detail !== undefined) {
    const d: NonNullable<CheckOutcome["detail"]> = {};
    if (c.detail.matched !== undefined) d.matched = c.detail.matched;
    if (c.detail.required !== undefined) d.required = c.detail.required;
    if (c.detail.tree_size !== undefined) d.treeSize = BigInt(c.detail.tree_size);
    out.detail = d;
  }
  return out;
}

function mapLineage(l: WireLineage): LineageStep {
  return {
    participantKind: l.participant_kind,
    participantId: l.participant_id,
    action: l.action,
    at: BigInt(l.at),
  };
}

function mapEstablished(e: WireEstablished): Established {
  const out: Established = {
    unalteredSinceCapture: e.unaltered_since_capture,
    signedBy: e.signed_by,
  };
  if (e.existed_at_or_before !== undefined) out.existedAtOrBefore = BigInt(e.existed_at_or_before);
  if (e.lineage !== undefined) out.lineage = e.lineage.map(mapLineage);
  if (e.bound_subject_digest !== undefined) {
    out.boundSubjectDigest = {
      alg: e.bound_subject_digest.alg,
      bytes: fromHex(e.bound_subject_digest.bytes_hex),
    };
  }
  if (e.log_origin !== undefined) out.logOrigin = e.log_origin;
  return out;
}

function mapNotEstablished(n: WireNotEstablished): NotEstablished {
  return {
    validityOfRecord: n.validity_of_record,
    faithfulness: n.faithfulness,
    authorshipTruth: n.authorship_truth,
    completeness: n.completeness,
    timeUpperBoundOnly: n.time_upper_bound_only,
  };
}

function policyToWire(p: Policy): Record<string, unknown> {
  return {
    accepted_canon_versions: p.acceptedCanonVersions,
    // `max_clock_skew_ms` is a plain `i64` JSON number on the wire (not a decimal string); a clock-skew tolerance
    // is always small, so the bigint→number narrowing is lossless in practice.
    max_clock_skew_ms: Number(p.maxClockSkewMs),
    require_anchor: p.requireAnchor,
    required_witnesses: p.requiredWitnesses,
    ...(p.expectedSubjectDigest !== undefined
      ? {
          expected_subject_digest: {
            alg: p.expectedSubjectDigest.alg,
            bytes_hex: p.expectedSubjectDigest.bytesHex,
          },
        }
      : {}),
    ...(p.trustedKeys !== undefined ? { trusted_keys: p.trustedKeys } : {}),
    ...(p.logOrigin !== undefined ? { log_origin: p.logOrigin } : {}),
    ...(p.trustedLogKeys !== undefined ? { trusted_log_keys: p.trustedLogKeys } : {}),
    ...(p.requiredActions !== undefined ? { required_actions: p.requiredActions } : {}),
  };
}

/**
 * Offline end-to-end verification (§11). Returns a {@link VerificationResult} **value** — a tamper is `total:false`
 * with the full honesty report intact, never a throw; only malformed input throws a {@link ThoughtmarkError}.
 * `nowUnixMs` is the injected clock (read once). `anchorVerifier` is reserved (no verifier ships before Phase 4),
 * so passing one currently has no effect.
 */
export function verify(
  bundle: unknown,
  policy: Policy,
  nowUnixMs: bigint,
  _anchorVerifier?: unknown,
): VerificationResult {
  const input = enc.encode(
    JSON.stringify({
      bundle,
      env: { now_unix_ms: nowUnixMs.toString() },
      policy: policyToWire(policy),
    }),
  );
  const out = runOrThrow("verify", input);
  const w = JSON.parse(dec.decode(out)) as WireResult;
  return {
    schema: w.schema,
    verifiedAt: BigInt(w.verified_at),
    total: w.total,
    checks: w.checks.map(mapCheck),
    established: mapEstablished(w.established),
    notEstablished: mapNotEstablished(w.not_established),
  };
}

// ── frozen §14.6 verbs whose backends land in a later phase ─────────────────────────────────────────────────────
// Present so the typed surface is complete at 1.0; each throws until its backend is wired (additive MINOR, §14.7).

/** DSSE-wrap + sign an in-toto Statement (§7). Deferred: the typed `Signer` seam wires in a later phase. */
export function sign(): never {
  throw new ThoughtmarkError("INTERNAL");
}
/** Verify a DSSE envelope, returning the parsed Statement (§7). Deferred to the signing facade. */
export function verifyEnvelope(): never {
  throw new ThoughtmarkError("INTERNAL");
}
/** Selective-disclosure redaction (§9, `thoughtmark-redaction`). Deferred to Phase 5. */
export function redact(): never {
  throw new ThoughtmarkError("INTERNAL");
}
/** Lossy PROV-O / C2PA projection (§5); never re-hashed. Deferred to Phase 5. */
export function export_(): never {
  throw new ThoughtmarkError("INTERNAL");
}
/** Replay an opaque anchor receipt (§8, `thoughtmark-anchor`). Deferred to Phase 4. */
export function verifyAnchor(): never {
  throw new ThoughtmarkError("INTERNAL");
}
/** Submit a root to an anchoring backend (§8, async/shell). Deferred to Phase 4. */
export function anchor(): never {
  throw new ThoughtmarkError("INTERNAL");
}
