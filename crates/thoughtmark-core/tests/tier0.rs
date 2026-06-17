// SPDX-License-Identifier: Apache-2.0
//! Tier-0 integration tests for `thoughtmark-core`.
//!
//! Written without `unwrap`/`expect`/`panic` (comparing `Result`s directly) so the suite passes the crate's
//! no-panic wall unmodified. The headline test is the **differential oracle**: the in-house RFC 8785 encoder is
//! asserted byte-identical to the audited (std-only) `serde_json_canonicalizer` crate over arbitrary float-free
//! values — the guard that makes the in-house implementation trustworthy.

use proptest::prelude::*;
use serde_json::Value;
use thoughtmark_core::canon::{self, CanonError, HashAlg};
use thoughtmark_core::{ErrorCode, UnixMillis, ops};

// --- canonicalization --------------------------------------------------------------------------------------------

#[test]
fn sorts_keys_strips_whitespace() {
    assert_eq!(
        canon::canonicalize_str(r#"{ "b": 1, "a": 2 }"#),
        Ok(br#"{"a":2,"b":1}"#.to_vec())
    );
}

#[test]
fn utf16_sort_discriminates_from_codepoint_order() {
    // The serde_jcs-killer case. An astral key (U+1F600 = surrogate pair D83D DE00) vs a BMP key in
    // [U+E000, U+FFFF] is the ONLY pair where UTF-16 code-unit order DISAGREES with code-point / UTF-8 byte
    // order. UTF-16: first units 0xD83D < 0xFFFF, so 😀 sorts BEFORE ￿. Code-point / UTF-8: U+FFFF < U+1F600,
    // so a `char`-based (code-point) or UTF-8-byte sort would put ￿ first. This assertion therefore FAILS under
    // any non-UTF-16 sort — the regression that a `😀`-vs-`z` case (below) cannot catch.
    assert_eq!(
        canon::canonicalize_str("{\"\u{FFFF}\":1,\"\u{1F600}\":2}"),
        Ok("{\"\u{1F600}\":2,\"\u{FFFF}\":1}".as_bytes().to_vec())
    );
    // Non-discriminating sanity check (all three orders agree here: 0xD83D > 'z' = 0x007A).
    assert_eq!(
        canon::canonicalize_str("{\"\u{1F600}\":1,\"z\":2}"),
        Ok("{\"z\":2,\"\u{1F600}\":1}".as_bytes().to_vec())
    );
}

#[test]
fn escapes_per_rfc8785() {
    assert_eq!(
        canon::canonicalize_str("\"a\\u0001\\\"\\\\\\n\\t\""),
        Ok("\"a\\u0001\\\"\\\\\\n\\t\"".as_bytes().to_vec())
    );
    assert_eq!(
        canon::canonicalize_str("\"é\""),
        Ok("\"é\"".as_bytes().to_vec())
    );
}

#[test]
fn integers_normalize() {
    assert_eq!(canon::canonicalize_str("-0"), Ok(b"0".to_vec()));
    assert_eq!(
        canon::canonicalize_str("9007199254740991"),
        Ok(b"9007199254740991".to_vec())
    );
}

#[test]
fn canonicalize_is_idempotent() {
    let once = canon::canonicalize_str(r#"{"b":1,"a":[3,2,1],"c":{"y":1,"x":2}}"#);
    let reparsed = once
        .as_ref()
        .ok()
        .and_then(|b| core::str::from_utf8(b).ok())
        .map(canon::canonicalize_str);
    assert_eq!(reparsed, Some(once));
}

#[test]
fn rejects_duplicate_keys() {
    assert_eq!(
        canon::canonicalize_str(r#"{"a":1,"a":2}"#),
        Err(CanonError::DuplicateKey)
    );
    assert_eq!(
        canon::canonicalize_str(r#"{"x":{"c":1,"c":2}}"#),
        Err(CanonError::DuplicateKey)
    );
    assert_eq!(
        canon::canonicalize_str(r#"[1,{"a":1,"a":2}]"#),
        Err(CanonError::DuplicateKey)
    );
    assert!(canon::canonicalize_str(r#"{"a":1,"b":2}"#).is_ok());
}

#[test]
fn rejects_floats_and_big_ints() {
    assert_eq!(
        canon::canonicalize_str(r#"{"x":1.5}"#),
        Err(CanonError::FloatNotAllowed)
    );
    assert_eq!(
        canon::canonicalize_str(r#"{"x":1e3}"#),
        Err(CanonError::FloatNotAllowed)
    );
    assert_eq!(
        canon::canonicalize_str(r#"{"x":9007199254740993}"#),
        Err(CanonError::IntegerOutOfRange)
    );
}

#[test]
fn escapes_rare_c0_and_emits_del_raw() {
    // 0x0B (vertical tab) and 0x1F have NO short escape -> lowercase \u00XX.
    assert_eq!(
        canon::canonicalize_str("\"\\u000b\""),
        Ok("\"\\u000b\"".as_bytes().to_vec())
    );
    assert_eq!(
        canon::canonicalize_str("\"\\u001f\""),
        Ok("\"\\u001f\"".as_bytes().to_vec())
    );
    // U+007F (DEL) is NOT a C0 control; RFC 8785 emits it RAW (one byte 0x7f), never escaped.
    assert_eq!(
        canon::canonicalize_str("\"\\u007f\""),
        Ok(b"\"\x7f\"".to_vec())
    );
}

#[test]
fn integer_boundaries_are_pinned() {
    // 2^53 - 1 is the largest allowed; 2^53 and beyond are out of range (both signs).
    assert_eq!(
        canon::canonicalize_str("9007199254740991"),
        Ok(b"9007199254740991".to_vec())
    );
    assert_eq!(
        canon::canonicalize_str("9007199254740992"),
        Err(CanonError::IntegerOutOfRange)
    );
    assert_eq!(
        canon::canonicalize_str("-9007199254740991"),
        Ok(b"-9007199254740991".to_vec())
    );
    assert_eq!(
        canon::canonicalize_str("-9007199254740992"),
        Err(CanonError::IntegerOutOfRange)
    );
}

#[test]
fn negative_zero_float_is_rejected_but_integer_zero_normalizes() {
    // "-0.0" is a float -> rejected; "-0" is integer zero -> normalized to "0" (see `integers_normalize`).
    assert_eq!(
        canon::canonicalize_str("-0.0"),
        Err(CanonError::FloatNotAllowed)
    );
}

#[test]
fn nan_and_infinity_are_invalid_json() {
    assert_eq!(
        canon::canonicalize_str("{\"x\":NaN}"),
        Err(CanonError::InvalidJson)
    );
    assert_eq!(
        canon::canonicalize_str("{\"x\":Infinity}"),
        Err(CanonError::InvalidJson)
    );
    assert_eq!(
        canon::canonicalize_str("{\"x\":-Infinity}"),
        Err(CanonError::InvalidJson)
    );
}

// --- hashing, domains, salt, cid ---------------------------------------------------------------------------------

#[test]
fn hash_is_stable_over_canonicalization() {
    let a = canon::canonicalize_str(r#"{"b":1,"a":2}"#);
    let b = canon::canonicalize_str(r#"{"a":2,"b":1}"#);
    let ha = a.map(|bytes| canon::hash(&bytes).bytes);
    let hb = b.map(|bytes| canon::hash(&bytes).bytes);
    assert_eq!(ha, hb);
}

#[test]
fn digest_wire_shape_is_exact() {
    let d = canon::hash(b"abc");
    let json = canon::canonicalize(&d);
    assert!(matches!(
        &json,
        Ok(bytes) if bytes.starts_with(br#"{"alg":"blake3","bytes_hex":""#)
    ));
    assert_eq!(d.to_hex().len(), 64);
}

#[test]
fn digest_multihash_layout() {
    let d = canon::hash(b"abc");
    let mh = d.multihash_bytes();
    assert_eq!(mh.len(), 34);
    assert_eq!(mh.first(), Some(&0x1eu8)); // blake3 multihash code
    assert_eq!(mh.get(1), Some(&0x20u8)); // length 32
    assert_eq!(mh.get(2..), Some(&d.bytes[..]));
}

#[test]
fn digest_deserialize_fails_closed() {
    assert!(serde_json::from_str::<canon::Digest>(r#"{"alg":"md5","bytes_hex":"00"}"#).is_err());
    assert!(serde_json::from_str::<canon::Digest>(r#"{"alg":"blake3","bytes_hex":"00"}"#).is_err());
}

#[test]
fn domain_prefix_is_exact_and_bound() {
    assert_eq!(
        canon::domain::prefix(HashAlg::Blake3, canon::domain::TURN),
        b"tm-jcs-1:blake3:thoughtmark.turn:"
    );
    assert_eq!(canon::CANON_VERSION, "tm-jcs-1");
    let canonical = b"{\"a\":1}";
    let bound = canon::hash_domain(HashAlg::Blake3, canon::domain::TURN, canonical);
    assert_ne!(bound.bytes, canon::hash(canonical).bytes);
}

#[test]
fn cid_is_base32_lower_and_length_pinned() {
    let s = canon::cid_blob(HashAlg::Blake3, b"abc").and_then(|c| canon::cid_to_string(&c));
    assert!(matches!(&s, Ok(text) if text.starts_with('b')));
    let reparsed = s.as_ref().ok().map(|text| canon::cid_from_str(text));
    assert!(matches!(reparsed, Some(Ok(_))));
    assert!(canon::cid_from_str("not-a-cid").is_err());
}

#[test]
fn salt_is_mixed_in() {
    let a = canon::salted_content_digest(HashAlg::Blake3, &canon::Salt([0u8; 32]), b"hi");
    let b = canon::salted_content_digest(HashAlg::Blake3, &canon::Salt([1u8; 32]), b"hi");
    assert_ne!(a.bytes, b.bytes);
}

// --- error model + ops envelope ----------------------------------------------------------------------------------

#[test]
fn error_code_as_str_matches_serde_token() {
    let all = [
        ErrorCode::CanonInvalidJson,
        ErrorCode::CanonNonDeterministicFloat,
        ErrorCode::CanonIntegerOutOfRange,
        ErrorCode::UnknownCanonVersion,
        ErrorCode::UnknownHashAlg,
        ErrorCode::DigestMismatch,
        ErrorCode::CidMalformed,
        ErrorCode::Internal,
    ];
    for code in all {
        let token = serde_json::to_value(code)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned));
        assert_eq!(token.as_deref(), Some(code.as_str()));
        let back =
            serde_json::from_value::<ErrorCode>(Value::String(code.as_str().to_owned())).ok();
        assert_eq!(back, Some(code));
    }
}

#[test]
fn run_op_error_envelopes_embed_the_code() {
    assert_eq!(
        ops::run_op("canonicalize", br#"{"x":1.5}"#),
        br#"{"ok":false,"error":{"code":"CANON_NON_DETERMINISTIC_FLOAT"}}"#
    );
    assert_eq!(
        ops::run_op("canonicalize", br#"{"a":1,"a":2}"#),
        br#"{"ok":false,"error":{"code":"CANON_INVALID_JSON"}}"#
    );
    assert_eq!(
        ops::run_op("frobnicate", b""),
        br#"{"ok":false,"error":{"code":"INTERNAL"}}"#
    );
}

#[test]
fn unix_millis_is_a_decimal_string() {
    let v = UnixMillis(9_007_199_254_740_993);
    assert_eq!(
        serde_json::to_value(v).ok(),
        Some(Value::String("9007199254740993".to_owned()))
    );
    assert_eq!(
        serde_json::from_value::<UnixMillis>(Value::String("9007199254740993".to_owned())).ok(),
        Some(v)
    );
    assert!(serde_json::from_value::<UnixMillis>(serde_json::json!(5)).is_err());
}

#[test]
fn unix_millis_accepts_negative_and_rejects_noncanonical() {
    // Pre-epoch (negative) values round-trip.
    assert_eq!(
        serde_json::from_value::<UnixMillis>(Value::String("-123".to_owned())).ok(),
        Some(UnixMillis(-123))
    );
    // Canonical "0" is accepted.
    assert_eq!(
        serde_json::from_value::<UnixMillis>(Value::String("0".to_owned())).ok(),
        Some(UnixMillis(0))
    );
    // Non-canonical decimal strings fail closed (leading zeros, "-0", leading '+', float, hex, whitespace, empty).
    for bad in ["007", "-0", "+5", "00", "1.0", "0x10", " 5", ""] {
        assert!(
            serde_json::from_value::<UnixMillis>(Value::String(bad.to_owned())).is_err(),
            "expected rejection of {bad:?}"
        );
    }
}

// --- THE differential oracle -------------------------------------------------------------------------------------

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-9_007_199_254_740_991i64..=9_007_199_254_740_991i64)
            .prop_map(|i| Value::Number(i.into())),
        ".*".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::hash_map(".*", inner, 0..5)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// The in-house encoder is byte-identical to the audited `serde_json_canonicalizer` for every float-free
    /// value — the guard over the UTF-16 key sort and C0 escaping. A mismatch is a real bug, never papered over.
    #[test]
    fn in_house_matches_serde_json_canonicalizer(v in arb_json()) {
        let ours = canon::canonicalize_value(&v).ok();
        let oracle = serde_json_canonicalizer::to_vec(&v).ok();
        prop_assert!(oracle.is_some());
        prop_assert_eq!(ours, oracle);
    }

    /// Canonicalization is idempotent on its own output.
    #[test]
    fn canonicalize_value_idempotent(v in arb_json()) {
        let once = canon::canonicalize_value(&v).ok();
        let twice = once
            .as_ref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
            .and_then(|parsed| canon::canonicalize_value(&parsed).ok());
        prop_assert_eq!(once, twice);
    }

    /// `hash(canonicalize(x))` is stable: the digest is invariant to input key order and to re-parsing the
    /// canonical bytes — the property the conformance corpus relies on for cross-language hash equality.
    #[test]
    fn hash_of_canonicalize_is_stable(v in arb_json()) {
        let canon1 = canon::canonicalize_value(&v).ok();
        let h1 = canon1.as_ref().map(|b| canon::hash(b).bytes);
        let h2 = canon1
            .as_ref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
            .and_then(|parsed| canon::canonicalize_value(&parsed).ok())
            .map(|b| canon::hash(&b).bytes);
        prop_assert_eq!(h1, h2);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// `validate_no_float` rejects every JSON float — both decimal-point and exponent forms — through the
    /// `canonicalize_str` boundary. (Float tokens are synthesized as strings so the test never names `f64`, which
    /// the `disallowed-types` wall forbids even here.)
    #[test]
    fn validate_no_float_rejects_every_float(int in 0u64..=1_000_000u64, frac in 0u64..=1_000_000u64) {
        prop_assert_eq!(
            canon::canonicalize_str(&format!("{int}.{frac}")),
            Err(CanonError::FloatNotAllowed)
        );
        prop_assert_eq!(
            canon::canonicalize_str(&format!("{int}e{frac}")),
            Err(CanonError::FloatNotAllowed)
        );
    }

    /// `validate_no_float` rejects every integer outside the I-JSON safe range `[-(2^53-1), 2^53-1]`.
    #[test]
    fn validate_no_float_rejects_oversized_ints(
        i in prop_oneof![9_007_199_254_740_992i64..=i64::MAX, i64::MIN..=-9_007_199_254_740_992i64],
    ) {
        prop_assert_eq!(
            canon::canonicalize_value(&Value::Number(i.into())),
            Err(CanonError::IntegerOutOfRange)
        );
    }
}
