//! # Cipher Suites
//!
//! This module provides pre-configured cipher suites for various elliptic curves.
//! Each suite is conditionally compiled based on its corresponding feature flag.
//!
//! ## Available Suites
//!
//! - **Ed25519**: Edwards curve with SHA-512 hash function and Try-And-Increment (TAI)
//!   hash-to-curve method. Supports Tiny, Thin, and Pedersen VRF schemes.
//!
//! - **Secp256r1**: NIST P-256 curve with SHA-256 hash function and TAI hash-to-curve
//!   method. Supports Tiny, Thin, and Pedersen VRF schemes.
//!
//! - **Bandersnatch**: Edwards curve defined over the BLS12-381 scalar field with
//!   SHA-512 hash function. Supports Tiny, Thin, Pedersen, and Ring VRF schemes.
//!   Available in both Edwards and Short Weierstrass forms.
//!
//! - **JubJub**: Edwards curve defined over the BLS12-381 scalar field with
//!   SHA-512 hash function. Supports Tiny, Thin, Pedersen, and Ring VRF schemes.
//!
//! - **Baby-JubJub**: Edwards curve defined over the BN254 scalar field with
//!   SHA-512 hash function. Supports Tiny, Thin, Pedersen, and Ring VRF schemes.
//!   Optimized for Ethereum compatibility.

/// Suite identifier.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SuiteId {
    /// Suite version
    pub version: u8,
    /// Elliptic curve
    pub curve: u8,
    /// Hash function
    pub hash: u8,
    /// Hash-to-curve method
    pub h2c: u8,
}

impl SuiteId {
    pub const fn new(version: u8, curve: u8, hash: u8, h2c: u8) -> Self {
        Self {
            version,
            curve,
            hash,
            h2c,
        }
    }

    pub const fn to_bytes(&self) -> [u8; 4] {
        [self.version, self.curve, self.hash, self.h2c]
    }
}

impl core::fmt::LowerHex for SuiteId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let v = u32::from_le_bytes(self.to_bytes());
        core::fmt::LowerHex::fmt(&v, f)
    }
}

// Suite ID component constants.

/// Curve identifiers.
pub mod curve {
    pub const BANDERSNATCH: u8 = 0x01;
    pub const BANDERSNATCH_SW: u8 = 0x02;
    pub const ED25519: u8 = 0x03;
    pub const JUBJUB: u8 = 0x04;
    pub const BABY_JUBJUB: u8 = 0x05;
    pub const SECP256R1: u8 = 0x06;
    pub const TESTING: u8 = 0xFF;
}

/// Hash function identifiers.
pub mod hash {
    pub const SHA512: u8 = 0x01;
    pub const SHA256: u8 = 0x02;
    pub const BLAKE3: u8 = 0x03;
    pub const SHAKE128: u8 = 0x04;
}

/// Hash-to-curve method identifiers.
pub mod h2c {
    pub const ELL2: u8 = 0x01;
    pub const TAI: u8 = 0x02;
}

#[cfg(test)]
pub(crate) mod testing;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "secp256r1")]
pub mod secp256r1;

#[cfg(feature = "bandersnatch")]
pub mod bandersnatch;
#[cfg(all(feature = "bandersnatch", feature = "blake3"))]
pub mod bandersnatch_blake3;
#[cfg(all(feature = "bandersnatch", feature = "shake128"))]
pub mod bandersnatch_shake128;
#[cfg(feature = "bandersnatch")]
pub mod bandersnatch_sw;

#[cfg(feature = "jubjub")]
pub mod jubjub;

#[cfg(feature = "baby-jubjub")]
pub mod baby_jubjub;
