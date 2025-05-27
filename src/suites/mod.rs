//! # Cipher Suites
//!
//! This module provides pre-configured cipher suites for various elliptic curves.
//! Each suite is conditionally compiled based on its corresponding feature flag.
//!
//! ## Available Suites
//!
//! - **Ed25519**: Edwards curve with SHA-512 hash function and Try-And-Increment (TAI)
//!   hash-to-curve method. Supports IETF and Pedersen VRF schemes.
//!
//! - **Secp256r1**: NIST P-256 curve with SHA-256 hash function and TAI hash-to-curve
//!   method. Supports IETF and Pedersen VRF schemes. Uses SEC1 point encoding.
//!
//! - **Bandersnatch**: Edwards curve defined over the BLS12-381 scalar field with
//!   SHA-512 hash function. Supports IETF, Pedersen, and Ring VRF schemes.
//!   Available in both Edwards and Short Weierstrass forms.
//!
//! - **JubJub**: Edwards curve defined over the BLS12-381 scalar field with
//!   SHA-512 hash function. Supports IETF, Pedersen, and Ring VRF schemes.
//!
//! - **Baby-JubJub**: Edwards curve defined over the BN254 scalar field with
//!   SHA-512 hash function. Supports IETF, Pedersen, and Ring VRF schemes.
//!   Optimized for Ethereum compatibility.

#[cfg(test)]
pub(crate) mod testing;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "secp256r1")]
pub mod secp256r1;

#[cfg(feature = "bandersnatch")]
pub mod bandersnatch;
#[cfg(feature = "bandersnatch")]
pub mod bandersnatch_sw;

#[cfg(feature = "jubjub")]
pub mod jubjub;

#[cfg(feature = "baby-jubjub")]
pub mod baby_jubjub;
