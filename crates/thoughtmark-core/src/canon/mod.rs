// SPDX-License-Identifier: Apache-2.0
//! Tier-0: canonicalization, hashing, content addressing (arch §4).
//!
//! The deterministic byte foundation: bytes in, bytes / `Result` out — no clock, no RNG-source, no network, no
//! float on the hashed path. The public surface is re-exported here.

pub mod cid;
pub mod digest;
pub mod domain;
pub mod error;
pub mod jcs;
pub mod nofloat;
pub mod salt;

pub use cid::{RAW_CODEC, cid_blob, cid_from_str, cid_to_string};
pub use digest::{Digest, HashAlg, hash, hash_with};
pub use domain::{CANON_VERSION, hash_domain, prefix};
pub use error::CanonError;
pub use jcs::{canonicalize, canonicalize_str, canonicalize_value};
pub use nofloat::validate_no_float;
pub use salt::{Salt, salted_content_digest};
