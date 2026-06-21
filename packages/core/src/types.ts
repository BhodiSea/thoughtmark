// SPDX-License-Identifier: Apache-2.0
/** Names of operations dispatched through the core (the `run_op` string-dispatch seam, byte-in/byte-out). */
export type OpName =
  | "canonicalize"
  | "hash_blake3"
  | "hash_sha256"
  | "cid_v1"
  | "hash_domain_turn"
  | "hash_domain_object"
  | "hash_domain_manifest"
  | "trail_root";
