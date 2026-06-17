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
                // Reject a leading '+', and any float/exponent syntax (`i64::from_str` already rejects those).
                if v.starts_with('+') {
                    return Err(E::custom("unix millis must not have a leading '+'"));
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
