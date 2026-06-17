// SPDX-License-Identifier: Apache-2.0
//! The injected-determinism runtime (arch §10.1, I3).
//!
//! Time and randomness never enter core logic ambiently. Time arrives through [`Clock`] as a [`UnixMillis`];
//! randomness arrives through an injected [`Rng`] (or the crypto-grade marker [`Csprng`]). The deterministic
//! `vectors`-gated implementations live in [`fixtures`]; the real `SystemClock` / `OsCsprng` live OUTSIDE the
//! audited core.

#[cfg(feature = "vectors")]
pub mod fixtures;

use alloc::string::ToString as _;
use core::fmt;

/// A source of wall-clock time, injected so core logic stays deterministic.
pub trait Clock {
    /// The current time, in milliseconds since the Unix epoch.
    fn now(&self) -> UnixMillis;
}

/// A source of bytes, injected so core logic never touches an ambient RNG (I3).
pub trait Rng {
    /// Fill `dst` entirely with bytes from this source.
    fn fill_bytes(&mut self, dst: &mut [u8]);
}

/// Marker for a cryptographically secure [`Rng`]. Salt/key minting requires this bound, so a non-crypto generator
/// (e.g. a plain seeded PRNG) can never be used where crypto-grade randomness is required.
pub trait Csprng: Rng {}

/// Milliseconds since the Unix epoch.
///
/// Stored as an `i64` for integer comparisons, but serialized AS A DECIMAL STRING (`"1750000000000"`), never a
/// JSON number — so values beyond `2^53` never violate I4 / I-JSON and round-trip through JS `BigInt`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UnixMillis(pub i64);

impl serde::Serialize for UnixMillis {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for UnixMillis {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DecimalStringVisitor;
        impl serde::de::Visitor<'_> for DecimalStringVisitor {
            type Value = UnixMillis;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a decimal string of milliseconds since the Unix epoch")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<UnixMillis, E> {
                // Accept ONLY the canonical decimal form, so a deserialized value re-serializes byte-identically:
                // no leading '+', no leading zeros ("007"), and no negative zero ("-0"). (`i64::from_str` also
                // rejects floats/exponents and a bare '-'; overflow still fails closed at `.parse()`.)
                if !is_canonical_decimal(v) {
                    return Err(E::custom(
                        "unix millis must be a canonical decimal integer (no leading '+', leading zeros, or '-0')",
                    ));
                }
                let n: i64 = v
                    .parse()
                    .map_err(|_| E::custom("invalid unix millis decimal string"))?;
                Ok(UnixMillis(n))
            }
        }
        // `deserialize_str` rejects a JSON number outright (forcing the string form, keeping I4).
        deserializer.deserialize_str(DecimalStringVisitor)
    }
}

/// True iff `v` is the canonical decimal form of an integer: an optional leading `-`, then either a single `0`
/// or a non-zero leading digit followed by digits. Rejects leading `+`, leading zeros, and `-0`. Iterates
/// `chars` (no slicing/indexing) to stay inside the no-panic wall.
fn is_canonical_decimal(v: &str) -> bool {
    let mut chars = v.chars();
    let Some(mut first) = chars.next() else {
        return false; // empty
    };
    let negative = first == '-';
    if negative {
        let Some(c) = chars.next() else {
            return false; // bare "-"
        };
        first = c;
    }
    if !first.is_ascii_digit() {
        return false; // leading '+', whitespace, sign-only, etc.
    }
    if first == '0' {
        // A leading zero is canonical ONLY as the standalone "0" — never "-0", "00", or "007".
        return !negative && chars.next().is_none();
    }
    // Non-zero leading digit: every remaining char must be a digit.
    chars.all(|c| c.is_ascii_digit())
}
