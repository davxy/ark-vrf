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
//! - **Thin VRF**: Compact VRF using a delinearized DLEQ proof, derived from the PedVRF
//!   construction in Section 4 of [BCHSV23](https://eprint.iacr.org/2023/002) with
//!   `b = 0` and `pk = sk*G` (see page 13)
//!
//! - **Pedersen VRF**: Key-hiding VRF using Pedersen commitments, based on the PedVRF
//!   construction from Section 4 of [BCHSV23](https://eprint.iacr.org/2023/002)
//!
//! - **Ring VRF**: Zero-knowledge VRF with signer anonymity within a key set, based on
//!   Sections 4 and 6 of [BCHSV23](https://eprint.iacr.org/2023/002)
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
//! let hash_bytes: [u8; 32] = output.hash();
//! ```
//!
//! ## Features
//!
//! - `default`: `std`
//! - `full`: Enables all features listed below except `secret-split`, `parallel`, `asm`, `test-vectors`.
//! - `secret-split`: Point scalar multiplication with secret split. Secret scalar is split into the sum
//!   of two scalars, which randomly mutate but retain the same sum. Incurs 2x penalty in some internal
//!   sensible scalar multiplications, but provides side channel defenses.
//! - `ring`: Ring-VRF for the curves supporting it.
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

use generic_array::typenum::Unsigned;
use utils::transcript::Transcript;
use zeroize::Zeroize;

pub mod codec;
pub mod ietf;
pub mod pedersen;
pub mod suites;
pub mod thin;
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
pub type HashOutput<S> =
    generic_array::GenericArray<u8, <<S as Suite>::Transcript as Transcript>::OutputSize>;

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
    type Affine: AffineRepr; // + utils::PointFromCoord;

    /// Fiat-Shamir transcript.
    ///
    /// Provides absorb/squeeze interface with ChaCha20 extension for
    /// unlimited output. Used for challenge generation, nonce derivation,
    /// delinearization, and other hash-based operations.
    type Transcript: Transcript;

    /// Overarching codec.
    ///
    /// Used wherever we need to encode/decode points and scalars.
    type Codec: codec::Codec<Self>;

    /// Generator used through all the suite.
    ///
    /// Defaults to Arkworks provided generator.
    #[inline(always)]
    fn generator() -> AffinePoint<Self> {
        Self::Affine::generator()
    }

    /// Nonce generation.
    ///
    /// Generates a deterministic pseudorandom nonce from the secret key,
    /// curve points, and additional data.
    ///
    /// When `transcript` is `Some`, uses the pre-built transcript (which may
    /// already carry shared state from earlier protocol steps). When `None`,
    /// constructs a fresh transcript.
    ///
    /// Utility functions available:
    /// - [`utils::nonce_rfc_8032`] — RFC-8032 section 5.1.6 (requires >= 64-byte hash output)
    /// - [`utils::nonce_transcript`] — Transcript-based deterministic nonce
    fn nonce(
        sk: &ScalarField<Self>,
        pts: &[&AffinePoint<Self>],
        ad: &[u8],
        transcript: Option<Self::Transcript>,
    ) -> ScalarField<Self>;

    /// Challenge generation.
    ///
    /// Hashes curve points and optional additional data to produce a scalar.
    ///
    /// When `transcript` is `Some`, uses the pre-built transcript (which may
    /// already carry shared state from earlier protocol steps). When `None`,
    /// constructs a fresh transcript from `SUITE_ID`.
    ///
    /// Utility functions available:
    /// - [`utils::challenge_rfc_9381`] — RFC-9381 section 5.4.3
    fn challenge(
        pts: &[&AffinePoint<Self>],
        ad: &[u8],
        transcript: Option<Self::Transcript>,
    ) -> ScalarField<Self>;

    /// Hash data to a curve point.
    ///
    /// The input `data` is assumed to be `[salt||]alpha` according to the RFC-9381.
    /// In other words, salt is not applied by this function.
    ///
    /// Utility functions available:
    /// - [`utils::hash_to_curve_tai_rfc_9381`] — try-and-increment
    /// - [`utils::hash_to_curve_ell2_rfc_9380`] — Elligator2
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>>;

    /// Map a curve point to a hash value.
    ///
    /// Utility functions available:
    /// - [`utils::point_to_hash_rfc_9381`] — RFC-9381 section 5.2 step 6
    fn point_to_hash<const N: usize>(pt: &AffinePoint<Self>) -> [u8; N];

    // TODO: add `sample()` to pick scalar with the given security bits .
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
    /// The seed is hashed using the suite's transcript, and the output is
    /// reduced modulo the curve's order to produce a valid scalar in the
    /// range `[1, n - 1]`. No clamping or multiplication by the cofactor is
    /// performed, regardless of the curve.
    ///
    /// The caller is responsible for ensuring that the resulting scalar is
    /// used safely with respect to the target curve's cofactor and subgroup
    /// properties.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut cnt = 0_u8;
        let scalar = loop {
            let mut transcript = S::Transcript::new(b"ark-vrf-keygen");
            transcript.absorb_raw(seed);
            if cnt > 0 {
                transcript.absorb_raw(&[cnt]);
            }
            let hash_len = <S::Transcript as Transcript>::OutputSize::to_usize();
            let mut bytes = ark_std::vec![0u8; hash_len];
            transcript.squeeze_raw(&mut bytes);
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

    /// Get the VRF input-output pair relative to input.
    pub fn vrf_io(&self, input: Input<S>) -> VrfIo<S> {
        VrfIo {
            input,
            output: self.output(input),
        }
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
    ///
    /// # Safety
    ///
    /// The caller must ensure that `value` was produced by a hash-to-curve
    /// procedure (or is otherwise not in a known discrete-log relation with
    /// the suite generator). This is required for the soundness of schemes
    /// like Thin-VRF where the input and generator are delinearized into a
    /// single check.
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
    pub fn hash<const N: usize>(&self) -> [u8; N] {
        S::point_to_hash(&self.0)
    }
}

/// VRF input-output pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VrfIo<S: Suite> {
    pub input: Input<S>,
    pub output: Output<S>,
}

impl<S: Suite> AsRef<[VrfIo<S>]> for VrfIo<S> {
    fn as_ref(&self) -> &[VrfIo<S>] {
        core::slice::from_ref(self)
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
        #[allow(dead_code)]
        pub type ThinProof = $crate::thin::Proof<$suite>;
        #[allow(dead_code)]
        pub type ThinBatchItem = $crate::thin::BatchItem<$suite>;
        #[allow(dead_code)]
        pub type ThinBatchVerifier = $crate::thin::BatchVerifier<$suite>;
        #[allow(dead_code)]
        pub type VrfIo = $crate::VrfIo<$suite>;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ietf::{Prover, Verifier};
    use ark_ec::AffineRepr;
    use suites::testing::{Input, Secret, TestSuite};
    use testing::{random_val, TEST_SEED};

    #[test]
    fn vrf_output_check() {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from_affine(random_val(Some(&mut rng)));
        let output = secret.output(input);

        let expected = "ceb5c6a77b7e790ea9493acb6d87625566b6301027d27e40dac1b24bed54c610";
        assert_eq!(expected, hex::encode(output.hash::<32>()));
    }

    #[test]
    fn prove_uniqueness_vulnerability() {
        use ark_ff::BigInteger;
        use ark_std::{One, Zero};

        type S = TestSuite;
        type Sc = ScalarField<S>;

        let secret = crate::Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::new(b"uniqueness attack").unwrap();
        let honest_output = secret.output(input);
        let ad = b"aux data";

        // 1. Find a low-order point L (order 2 for Ed25519)
        // For Ed25519, (0, -1) is order 2.
        let low_order_pt =
            AffinePoint::<S>::new_unchecked(BaseField::<S>::zero(), -BaseField::<S>::one());
        assert!(!low_order_pt.is_zero());
        // Verify it's order 2: 2 * L = O
        assert!((low_order_pt.into_group() + low_order_pt.into_group()).is_zero());

        // 2. Compute gamma' = gamma + L
        let malicious_output = Output::from_affine((honest_output.0 + low_order_pt).into_affine());
        assert_ne!(honest_output, malicious_output);
        assert_ne!(honest_output.hash::<32>(), malicious_output.hash::<32>());

        // 3. Forge a proof by grinding k until c is a multiple of 2 (so c*L = 0)
        //
        // Build the transcript exactly as verify does: vrf_transcript absorbs
        // the delinearized io and ad, then the challenge absorbs only the
        // public key and nonce commitments.
        let malicious_io = VrfIo {
            input,
            output: malicious_output,
        };
        let (t, _) = utils::vrf_transcript(malicious_io, ad);

        let mut ctr = 0u64;
        let (proof, _) = loop {
            let mut k_seed = [0u8; 8];
            k_seed.copy_from_slice(&ctr.to_le_bytes());
            let k = Sc::from_le_bytes_mod_order(&k_seed);

            let k_b = (S::generator() * k).into_affine();
            let k_h = (input.0 * k).into_affine();

            let c = S::challenge(&[&public.0, &k_b, &k_h], &[], Some(t.clone()));

            // We need c to be even so that c * L = identity (since L has order 2)
            if c.into_bigint().is_even() {
                let s = k + c * secret.scalar;
                break (crate::ietf::Proof { c, s }, c);
            }
            ctr += 1;
            if ctr > 1000 {
                panic!("Grinding failed");
            }
        };

        // 4. Verify the malicious proof
        assert!(public.verify(malicious_io, ad, &proof).is_ok());

        // 5. Verify the honest proof still works
        let honest_io = VrfIo {
            input,
            output: honest_output,
        };
        let honest_proof = secret.prove(honest_io, ad);
        assert!(public.verify(honest_io, ad, &honest_proof).is_ok());

        // SUCCESS! Two different outputs for the same input and public key!
        println!("Uniqueness BROKEN!");
        println!(
            "Honest output hash: {}",
            hex::encode(honest_output.hash::<32>())
        );
        println!(
            "Malicious output hash: {}",
            hex::encode(malicious_output.hash::<32>())
        );
    }
}
