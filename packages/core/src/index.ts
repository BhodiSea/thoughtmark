// SPDX-License-Identifier: Apache-2.0
// Public entry for @thoughtmark/core. The `browser` export condition routes to ./browser.js; Node and the
// type surface resolve here / to ./node.js.

// Runtime surface (init + the byte-airlock `runOp` + the typed §14.6 verbs, re-exported from the Node entry).
export {
  anchor,
  canonicalize,
  canonVersion,
  ensureReady,
  export_,
  hash,
  redact,
  runOp,
  sign,
  ThoughtmarkError,
  verify,
  verifyAnchor,
  verifyEnvelope,
} from "./node.js";
// The frozen §14.6 type surface.
export type {
  CanonVersion,
  CheckDetail,
  CheckKind,
  CheckOutcome,
  Digest,
  ErrorCode,
  Established,
  HashAlg,
  LineageStep,
  NotEstablished,
  OpName,
  Policy,
  TreeHash,
  VerificationResult,
} from "./types.js";
