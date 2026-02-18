//! # Elliptic Curve VRF-AD
//!
//! Implementations of Verifiable Random Functions with Additional Data (VRF-AD)
//! based on elliptic curve cryptography. Built on the [Arkworks](https://github.com/arkworks-rs)
//! framework with configurable cryptographic parameters.
//!
//! VRF-AD extends standard VRF constructions by binding auxiliary data to the proof,
//! providing stronger contextual security guarantees.
//!
//! ## Schemes
//!
//! - **IETF VRF**: ECVRF implementation compliant with [RFC9381](https://datatracker.ietf.org/doc/rfc9381)
//!
//! - **Pedersen VRF**: Key-hiding VRF using Pedersen commitments as described in
//!   [BCHSV23](https://eprint.iacr.org/2023/002)
//!
//! - **Ring VRF**: Zero-knowledge VRF with signer anonymity within a key set, based on
//!   [BCHSV23](https://eprint.iacr.org/2023/002)
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
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//!
//! let secret = Secret::from_seed(b"example seed");
//! let public = secret.public();
//! let input = Input::new(b"example input").unwrap();
//! let output = secret.output(input);
//! let hash_bytes = output.hash();
//! ```
//!
//! ### Proof Generation Schemes
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
use ark_ff::{PrimeField, Zero};
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

/// Suite's affine curve point type.
pub type AffinePoint<S> = <S as Suite>::Affine;
/// Suite's base field type.
pub type BaseField<S> = <AffinePoint<S> as AffineRepr>::BaseField;
/// Suite's scalar field type.
pub type ScalarField<S> = <AffinePoint<S> as AffineRepr>::ScalarField;
/// Suite's curve configuration type.
pub type CurveConfig<S> = <AffinePoint<S> as AffineRepr>::Config;

/// Suite's hash output type.
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
    type Hasher: Digest + Clone;

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
/// Contains the private scalar and cached public key.
/// Implements automatic zeroization on drop.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret<S: Suite> {
    /// Secret scalar.
    pub(crate) scalar: ScalarField<S>,
    /// Cached public key.
    pub(crate) public: Public<S>,
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

    /// Derives a `Secret` scalar deterministically from a seed.
    ///
    /// The seed is hashed using `Suite::Hasher`, and the output is reduced
    /// modulo the curve's order to produce a valid scalar in the range
    /// `[1, n - 1]`. No clamping or multiplication by the cofactor is
    /// performed, regardless of the curve.
    ///
    /// The caller is responsible for ensuring that the resulting scalar is
    /// used safely with respect to the target curve's cofactor and subgroup
    /// properties.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut cnt = 0_u8;
        let scalar = loop {
            let mut hasher = S::Hasher::new();
            hasher.update(seed);
            if cnt > 0 {
                hasher.update([cnt]);
            }
            let bytes = hasher.finalize();
            let scalar = ScalarField::<S>::from_le_bytes_mod_order(&bytes[..]);
            if !scalar.is_zero() {
                break scalar;
            }
            cnt += 1;
        };
        Self::from_scalar(scalar)
    }

    /// Construct an ephemeral `Secret` using the provided randomness source.
    pub fn from_rand(rng: &mut impl ark_std::rand::RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Get the secret scalar.
    pub fn scalar(&self) -> &ScalarField<S> {
        &self.scalar
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
/// Elliptic curve point representing the public component of a VRF key pair.
#[derive(Debug, Copy, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Public<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Public<S> {
    /// Construct from an affine point.
    pub fn from_affine(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

/// VRF input point generic over the cipher suite.
///
/// Elliptic curve point representing the VRF input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Input<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Input<S> {
    /// Construct from [`Suite::data_to_point`].
    ///
    /// Maps arbitrary data to a curve point via hash-to-curve.
    pub fn new(data: &[u8]) -> Option<Self> {
        S::data_to_point(data).map(Input)
    }
}

impl<S: Suite> Input<S> {
    /// Construct from an affine point.
    pub fn from_affine(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

/// VRF output point generic over the cipher suite.
///
/// Elliptic curve point representing the VRF output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Output<S> {
    /// Construct from an affine point.
    pub fn from_affine(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

impl<S: Suite> Output<S> {
    /// Hash the output point to a deterministic byte string.
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
        #[allow(dead_code)]
        pub type PedersenBatchItem = $crate::pedersen::BatchItem<$suite>;
        #[allow(dead_code)]
        pub type PedersenBatchVerifier = $crate::pedersen::BatchVerifier<$suite>;
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
        let input = Input::from_affine(random_val(Some(&mut rng)));
        let output = secret.output(input);

        let expected = "71c1b2ee6e46c59e3bd0e2f0e2852b90ab56abb223180b00bd6c8ec6b11af18c";
        assert_eq!(expected, hex::encode(output.hash()));
    }
}
