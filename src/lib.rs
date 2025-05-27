//! # Elliptic Curve VRF-AD
//!
//! This library provides flexible and efficient implementations of Verifiable
//! Random Functions with Additional Data (VRF-AD), a cryptographic construct
//! that augments a standard VRF scheme by incorporating auxiliary information
//! into its signature.
//!
//! It leverages the [Arkworks](https://github.com/arkworks-rs) framework and
//! supports customization of scheme parameters.
//!
//! ## What is a VRF?
//!
//! A Verifiable Random Function (VRF) is a cryptographic primitive that maps inputs
//! to verifiable pseudorandom outputs. Key properties include:
//!
//! - **Uniqueness**: For a given input and private key, there is exactly one valid output
//! - **Verifiability**: Anyone with the public key can verify that an output is correct
//! - **Pseudorandomness**: Without the private key, outputs appear random and unpredictable
//! - **Collision resistance**: Finding inputs that map to the same output is computationally infeasible
//!
//! ## Supported Schemes
//!
//! - **IETF VRF**: Complies with ECVRF described in [RFC9381](https://datatracker.ietf.org/doc/rfc9381).
//!   This is a standardized VRF implementation suitable for most applications requiring
//!   verifiable randomness.
//!
//! - **Pedersen VRF**: Described in [BCHSV23](https://eprint.iacr.org/2023/002).
//!   Extends the basic VRF with key-hiding properties using Pedersen commitments,
//!
//! - **Ring VRF**: A zero-knowledge-based scheme inspired by [BCHSV23](https://eprint.iacr.org/2023/002).
//!   Provides signer anonymity within a set of public keys (a "ring"), allowing
//!   verification that a ring member created the proof without revealing which specific member.
//!
//! ### Specifications
//!
//! - [VRF Schemes](https://github.com/davxy/bandersnatch-vrf-spec)
//! - [Ring Proof](https://github.com/davxy/ring-proof-spec)
//!
//! ## Built-In suites
//!
//! The library conditionally includes the following pre-configured suites (see features section):
//!
//! - **Ed25519-SHA-512-TAI**: Supports IETF and Pedersen VRF.
//! - **Secp256r1-SHA-256-TAI**: Supports IETF and Pedersen VRF.
//! - **Bandersnatch** (_Edwards curve on BLS12-381_): Supports IETF, Pedersen, and Ring VRF.
//! - **JubJub** (_Edwards curve on BLS12-381_): Supports IETF, Pedersen, and Ring VRF.
//! - **Baby-JubJub** (_Edwards curve on BN254_): Supports IETF, Pedersen, and Ring VRF.
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//!
//! // Create a secret key from a seed
//! let secret = Secret::from_seed(b"example seed");
//!
//! // Derive the corresponding public key
//! let public = secret.public();
//!
//! // Create an input by hashing data to a curve point
//! let input = Input::new(b"example input").unwrap();
//!
//! // Compute the VRF output (gamma point)
//! let output = secret.output(input);
//!
//! // The VRF output can be hashed to obtain a pseudorandom byte string:
//! let hash_bytes = output.hash();
//! ```
//!
//! - [ietf] vrf proof
//! - [pedersen] vrf proof
//! - [ring] vrf proof
//!
//! ## Features
//!
//! - `default`: `std`
//! - `full`: Enables all features listed below except `secret-split`, `parallel`, `asm`, `rfc-6979`, `test-vectors`.
//! - `secret-split`: Point scalar multiplication with secret split. Secret scalar is split into the sum
//!   of two scalars, which randomly mutate but retain the same sum. Incurs 2x penalty in some internal
//!   sensible scalar multiplications, but provides side channel defenses.
//! - `ring`: Ring-VRF for the curves supporting it.
//! - `rfc-6979`: Support for nonce generation according to RFC-9381 section 5.4.2.1.
//! - `test-vectors`: Deterministic ring-vrf proof. Useful for reproducible test vectors generation.
//!
//! ### Curves
//!
//! - `ed25519`
//! - `jubjub`
//! - `bandersnatch`
//! - `baby-jubjub`
//! - `secp256r1`
//!
//! ### Arkworks optimizations
//!
//! - `parallel`: Parallel execution where worth using `rayon`.
//! - `asm`: Assembly implementation of some low level operations.
//!
//! ## License
//!
//! Distributed under the [MIT License](./LICENSE).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use digest::Digest;
use zeroize::Zeroize;

pub mod codec;
pub mod ietf;
pub mod pedersen;
pub mod suites;
pub mod utils;

#[cfg(feature = "ring")]
pub mod ring;

#[cfg(test)]
mod testing;

/// Re-export stuff that may be useful downstream.
pub mod reexports {
    pub use ark_ec;
    pub use ark_ff;
    pub use ark_serialize;
    pub use ark_std;
}

use codec::Codec;

pub type AffinePoint<S> = <S as Suite>::Affine;
pub type BaseField<S> = <AffinePoint<S> as AffineRepr>::BaseField;
pub type ScalarField<S> = <AffinePoint<S> as AffineRepr>::ScalarField;
pub type CurveConfig<S> = <AffinePoint<S> as AffineRepr>::Config;

pub type HashOutput<S> = digest::Output<<S as Suite>::Hasher>;

/// Overarching errors.
#[derive(Debug)]
pub enum Error {
    /// Verification error
    VerificationFailure,
    /// Bad input data
    InvalidData,
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(_err: ark_serialize::SerializationError) -> Self {
        Error::InvalidData
    }
}

/// Defines a cipher suite.
///
/// This trait can be used to easily implement a VRF which follows the guidelines
/// given by RFC-9381 section 5.5.
///
/// Can be easily customized to implement more exotic VRF types by overwriting
/// the default methods implementations.
pub trait Suite: Copy {
    /// Suite identifier (aka `suite_string` in RFC-9381)
    const SUITE_ID: &'static [u8];

    /// Challenge encoded length.
    ///
    /// Must be at least equal to the Hash length.
    const CHALLENGE_LEN: usize;

    /// Curve point in affine representation.
    ///
    /// The point is guaranteed to be in the correct prime order subgroup
    /// by the `AffineRepr` bound.
    type Affine: AffineRepr;

    /// Overarching hasher.
    ///
    /// Used wherever an hash is required: nonce, challenge, MAC, etc.
    type Hasher: Digest;

    /// Overarching codec.
    ///
    /// Used wherever we need to encode/decode points and scalars.
    type Codec: codec::Codec<Self>;

    /// Nonce generation as described by RFC-9381 section 5.4.2.
    ///
    /// The default implementation provides the variant described
    /// by section 5.4.2.2 of RFC-9381 which in turn is a derived
    /// from steps 2 and 3 in section 5.1.6 of
    /// [RFC8032](https://tools.ietf.org/html/rfc8032).
    ///
    /// The algorithm generate the nonce value in a deterministic
    /// pseudorandom fashion.
    ///
    /// `Hasher` output **MUST** be be at least 64 bytes.
    ///
    /// # Panics
    ///
    /// This function panics if `Hasher` output is less than 64 bytes.
    #[inline(always)]
    fn nonce(sk: &ScalarField<Self>, pt: Input<Self>) -> ScalarField<Self> {
        utils::nonce_rfc_8032::<Self>(sk, &pt.0)
    }

    /// Challenge generation as described by RCF-9381 section 5.4.3.
    ///
    /// Hashes several points on the curve.
    ///
    /// This implementation extends the RFC procedure to allow adding
    /// some optional additional data too the hashing procedure.
    #[inline(always)]
    fn challenge(pts: &[&AffinePoint<Self>], ad: &[u8]) -> ScalarField<Self> {
        utils::challenge_rfc_9381::<Self>(pts, ad)
    }

    /// Hash data to a curve point.
    ///
    /// By default uses "try and increment" method described by RFC-9381.
    ///
    /// The input `data` is assumed to be `[salt||]alpha` according to the RFC-9381.
    /// In other words, salt is not applied by this function.
    #[inline(always)]
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }

    /// Map the point to a hash value using `Self::Hasher`.
    ///
    /// By default uses the algorithm described by RFC-9381 without cofactor clearing.
    #[inline(always)]
    fn point_to_hash(pt: &AffinePoint<Self>) -> HashOutput<Self> {
        utils::point_to_hash_rfc_9381::<Self>(pt, false)
    }

    /// Generator used through all the suite.
    ///
    /// Defaults to Arkworks provided generator.
    #[inline(always)]
    fn generator() -> AffinePoint<Self> {
        Self::Affine::generator()
    }
}

/// Secret key for VRF operations.
///
/// This structure contains the private scalar and caches the corresponding
/// public key. The scalar is automatically zeroized when the struct is dropped.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret<S: Suite> {
    // Secret scalar.
    pub scalar: ScalarField<S>,
    // Cached public point.
    pub public: Public<S>,
}

impl<S: Suite> Drop for Secret<S> {
    fn drop(&mut self) {
        self.scalar.zeroize()
    }
}

impl<S: Suite> CanonicalSerialize for Secret<S> {
    fn serialize_with_mode<W: ark_std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.scalar.serialized_size(compress)
    }
}

impl<S: Suite> CanonicalDeserialize for Secret<S> {
    fn deserialize_with_mode<R: ark_std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let scalar = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            reader, compress, validate,
        )?;
        Ok(Self::from_scalar(scalar))
    }
}

impl<S: Suite> ark_serialize::Valid for Secret<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.check()
    }
}

impl<S: Suite> Secret<S> {
    /// Construct a `Secret` from the given scalar.
    pub fn from_scalar(scalar: ScalarField<S>) -> Self {
        let public = Public((S::generator() * scalar).into_affine());
        Self { scalar, public }
    }

    /// Construct a `Secret` from the given seed.
    ///
    /// The `seed` is hashed using the `Suite::hash` to construct the secret scalar.
    pub fn from_seed(seed: &[u8]) -> Self {
        let bytes = utils::hash::<S::Hasher>(seed);
        let mut scalar = ScalarField::<S>::from_le_bytes_mod_order(&bytes[..]);
        if scalar.is_zero() {
            scalar.set_one();
        }
        Self::from_scalar(scalar)
    }

    /// Construct an ephemeral `Secret` using the provided randomness source.
    pub fn from_rand(rng: &mut impl ark_std::rand::RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Get the associated public key.
    pub fn public(&self) -> Public<S> {
        self.public
    }

    /// Get the VRF output point relative to input.
    pub fn output(&self, input: Input<S>) -> Output<S> {
        Output(smul!(input.0, self.scalar).into_affine())
    }
}

/// Public key generic over the cipher suite.
///
/// This is the public component of a VRF key pair, represented as a point on an elliptic curve.
/// It's used for verifying VRF proofs and can be safely shared publicly.
#[derive(Debug, Copy, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Public<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Public<S> {
    /// Construct from inner affine point.
    ///
    /// This allows creating a public key from an existing curve point.
    pub fn from(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

/// VRF input point generic over the cipher suite.
///
/// This represents an input to the VRF, which is a point on the elliptic curve.
/// Typically created by hashing arbitrary data to a curve point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Input<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Input<S> {
    /// Construct from [`Suite::data_to_point`].
    ///
    /// This maps arbitrary input data to a curve point using the suite's hash-to-curve function.
    /// Returns `None` if the data cannot be mapped to a valid curve point.
    pub fn new(data: &[u8]) -> Option<Self> {
        S::data_to_point(data).map(Input)
    }

    /// Construct from inner affine point.
    ///
    /// This allows creating an input from an existing curve point.
    pub fn from(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

/// VRF output point generic over the cipher suite.
///
/// This represents the output of the VRF evaluation, which is a point on the elliptic curve.
/// The output can be hashed to produce a deterministic byte string for applications
/// requiring uniform randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Output<S> {
    /// Construct from inner affine point.
    ///
    /// This allows creating an output from an existing curve point.
    pub fn from(value: AffinePoint<S>) -> Self {
        Self(value)
    }

    /// Hash the output point to produce a deterministic byte string.
    ///
    /// This converts the elliptic curve point to a uniform byte string using
    /// the suite's point-to-hash function. The resulting bytes can be used
    /// as pseudorandom values for applications.
    pub fn hash(&self) -> HashOutput<S> {
        S::point_to_hash(&self.0)
    }
}

/// Type aliases for the given suite.
#[macro_export]
macro_rules! suite_types {
    ($suite:ident) => {
        #[allow(dead_code)]
        pub type Secret = $crate::Secret<$suite>;
        #[allow(dead_code)]
        pub type Public = $crate::Public<$suite>;
        #[allow(dead_code)]
        pub type Input = $crate::Input<$suite>;
        #[allow(dead_code)]
        pub type Output = $crate::Output<$suite>;
        #[allow(dead_code)]
        pub type AffinePoint = $crate::AffinePoint<$suite>;
        #[allow(dead_code)]
        pub type ScalarField = $crate::ScalarField<$suite>;
        #[allow(dead_code)]
        pub type BaseField = $crate::BaseField<$suite>;
        #[allow(dead_code)]
        pub type IetfProof = $crate::ietf::Proof<$suite>;
        #[allow(dead_code)]
        pub type PedersenProof = $crate::pedersen::Proof<$suite>;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::{Input, Secret};
    use testing::{TEST_SEED, random_val};

    #[test]
    fn vrf_output_check() {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_val(Some(&mut rng)));
        let output = secret.output(input);

        let expected = "71c1b2ee6e46c59e3bd0e2f0e2852b90ab56abb223180b00bd6c8ec6b11af18c";
        assert_eq!(expected, hex::encode(output.hash()));
    }
}
