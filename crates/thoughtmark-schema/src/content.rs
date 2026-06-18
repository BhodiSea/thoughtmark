// SPDX-License-Identifier: Apache-2.0
//! Content parts (arch §5.6, verdict #2).
//!
//! A turn's content is a multi-part `Vec<ContentPart>` — "text + 2 images + a tool result" is normal, and
//! per-invocation tool provenance is first-class via [`ContentPart::ToolCall`]. The salt-bearing
//! [`ContentDigest::Hashed`] carries **only** `digest_hex` — there is structurally NO `salt_hex` field, so the
//! salt stays off-ledger and the content is crypto-shreddable (I5, arch §4.7). The tagged-enum `kind`
//! discriminant matches the §5.11 worked example (`"kind":"content"`, `"kind":"tool_call"`, `"kind":"hashed"`,
//! `"kind":"cid"`).

use alloc::string::String;
use thoughtmark_core::{Digest, HashAlg};

/// One part of a turn's content.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentPart {
    /// Text/image/audio/pdf content, referenced by salted-hash commitment or CID.
    Content {
        /// The IANA media type (e.g. `"text/plain"`, `"image/png"`).
        media_type: String,
        /// The commitment to the content bytes.
        body: ContentDigest,
    },
    /// A specific tool INVOCATION, with hashed args/result/error (no content on-ledger).
    ToolCall {
        /// The tool that was invoked.
        tool: ToolRef,
        /// A salted commitment to the call arguments.
        args_digest: Digest,
        /// A salted commitment to the result, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        result_digest: Option<Digest>,
        /// A salted commitment to an error, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<Digest>,
    },
}

/// A commitment to content bytes.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentDigest {
    /// A salted content commitment. NO `salt_hex` — the salt lives off-ledger (I5, arch §4.7).
    Hashed {
        /// The hash algorithm used.
        alg: HashAlg,
        /// The 64-char lowercase-hex salted digest.
        digest_hex: String,
    },
    /// A CIDv1 (raw codec) reference for binary/multimodal blobs.
    Cid {
        /// The base32-lower CIDv1 string.
        cid: String,
    },
}

/// A reference to an invoked or available tool.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRef {
    /// The tool name (e.g. `"pubmed_search"`).
    pub name: String,
    /// The tool version (e.g. `"2.1.0"`).
    pub version: String,
    /// An optional hash of the tool binary/spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
}
