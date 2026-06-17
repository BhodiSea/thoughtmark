// SPDX-License-Identifier: Apache-2.0
//! Deterministic, `vectors`-gated implementations of the determinism traits (arch §10.1).
//!
//! These exist ONLY behind the `vectors` feature (off by default), so production can never reproduce a real
//! salt/key from a test seed and the wasm/alloc closure never links a CSPRNG. [`SeededRng`] is deliberately NOT a
//! [`Csprng`]; only [`VectorCsprng`] carries that marker, and only here.

use super::{Clock, Csprng, Rng, UnixMillis};
use rand_core::{RngCore as _, SeedableRng as _};

/// A [`Clock`] frozen at a fixed instant — the deterministic time source for conformance vectors.
pub struct FixedClock(pub UnixMillis);

impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

/// A seeded ChaCha20 byte generator. Deterministic from its seed and reproducible across platforms. Deliberately
/// implements [`Rng`] but NOT [`Csprng`] — it must never be mistaken for a crypto-grade entropy source.
pub struct SeededRng(rand_chacha::ChaCha20Rng);

impl SeededRng {
    /// Construct from a 32-byte seed. Needs no entropy source (no `getrandom`).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SeededRng(rand_chacha::ChaCha20Rng::from_seed(seed))
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst);
    }
}

/// A [`Csprng`] wrapper around [`SeededRng`] for vector generation only. Gated to `vectors` so production cannot
/// mint a real salt or key from a test seed.
pub struct VectorCsprng(SeededRng);

impl VectorCsprng {
    /// Construct from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        VectorCsprng(SeededRng::from_seed(seed))
    }
}

impl Rng for VectorCsprng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst);
    }
}

impl Csprng for VectorCsprng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_rng_is_deterministic() {
        let mut a = SeededRng::from_seed([7u8; 32]);
        let mut b = SeededRng::from_seed([7u8; 32]);
        let (mut x, mut y) = ([0u8; 16], [0u8; 16]);
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);
    }

    #[test]
    fn fixed_clock_returns_its_instant() {
        let c = FixedClock(UnixMillis(42));
        assert_eq!(c.now(), UnixMillis(42));
    }
}
