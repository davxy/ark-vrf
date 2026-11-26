//! # Elliptic Curve VRF
//!
//! Verifiable random functions with additional data (VRF-AD) on
//! [arkworks](https://github.com/arkworks-rs) curves, with `no_std` support.
//! All schemes use a transcript-based Fiat-Shamir transform and accept several
//! input/output pairs in one proof.
//!
//! ## Security
//!
//! Build each VRF input with [`Input::new`], on the prover side and on the
//! verifier side. Nobody may know the discrete log of an input to the
//! generator: a prover who knows it can forge outputs.
//!
//! The verifiers do not check subgroup membership. See [`PointWrapper`] for
//! the points that are checked and the points that are not.
//!
//! ## Schemes
//!
//! - **Tiny VRF**: compact proof `(c, s)`, close to
//!   [RFC 9381](https://datatracker.ietf.org/doc/rfc9381).
//! - **Thin VRF**: proof `(R, s)`, with batch verification.
//! - **Pedersen VRF**: the public key is hidden in a Pedersen commitment
//!   ([BCHSV23](https://eprint.iacr.org/2023/002)).
//! - **Ring VRF**: Pedersen VRF plus a proof that the committed key is in a ring
//!   ([CSSV22](https://eprint.iacr.org/2022/1205)).
//!
//! ### Specifications
//!
//! - [VRF Schemes](https://github.com/davxy/bandersnatch-vrf-spec)
//! - [Ring Proof](https://github.com/davxy/ring-proof-spec)
//!
//! ## Built-In suites
//!
//! Each suite has a feature (see below).
//!
//! - **Ed25519**: Tiny, Thin and Pedersen VRF.
//! - **Secp256r1**: Tiny, Thin and Pedersen VRF.
//! - **Bandersnatch** (_Edwards curve on BLS12-381_): Tiny, Thin, Pedersen and
//!   Ring VRF. `bandersnatch_v2` uses the RFC 9380 `expand_message_xmd` padding.
//!   The [specification](https://github.com/davxy/bandersnatch-vrf-spec)
//!   recommends version 1.
//! - **JubJub** (_Edwards curve on BLS12-381_): Tiny, Thin, Pedersen and Ring VRF.
//! - **Baby-JubJub** (_Edwards curve on BN254_): Tiny, Thin, Pedersen and Ring
//!   VRF.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//!
//! let secret = Secret::from_seed([0; 32]);
//! let public = secret.public();
//! let input = Input::new(b"example input").unwrap();
//! let output = secret.output(input);
//! let hash_bytes: [u8; 32] = output.hash();
//! ```
//!
//! ## Features
//!
//! - `default`: `std`
//! - `full`: all the curves below, and `ring`.
//! - `secret-split`: each secret scalar multiplication of Tiny, Thin and
//!   Pedersen VRF (public key, output, nonce, blinding) uses two random shares
//!   of the scalar. This protects the scalar value against side channels, at
//!   twice the cost. The timing stays variable. Ring proof witness generation
//!   does not use the split.
//!   The shares come from `OsRng` at each multiplication, also when a `Secret`
//!   is decoded, and `OsRng` panics when its backend fails. The feature works
//!   with `no_std`, but where `getrandom` has no backend, the application must
//!   select one: `getrandom/js` on `wasm32-unknown-unknown`, `getrandom/custom`
//!   or `getrandom/rdrand` on bare metal.
//! - `ring`: Ring VRF for the curves that support it.
//! - `shake128`: `Shake128Transcript` and the `bandersnatch_shake128` suite.
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
//! - `parallel`: parallel execution with `rayon`.
//! - `asm`: assembly for some low level operations.
//!
//! ## License
//!
//! Distributed under the [MIT License](./LICENSE).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![cfg_attr(not(test), warn(missing_docs))]

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::marker::PhantomData;

pub use utils::canonical::CanonicalDeserializeExact;
use utils::canonical::CanonicalDeserializeStrict;
use utils::smul;
use utils::transcript::Transcript;
use zeroize::Zeroize;

pub mod pedersen;
pub mod suites;
pub mod thin;
pub mod tiny;
pub mod utils;

#[cfg(feature = "ring")]
pub mod ring;

#[cfg(test)]
mod testing;

#[cfg(all(test, not(feature = "std")))]
compile_error!(
    "the test suite needs the `std` feature: run `cargo test` with the default features"
);

/// Re-export stuff that may be useful downstream.
pub mod reexports {
    pub use ark_ec;
    pub use ark_ff;
    pub use ark_serialize;
    pub use ark_std;
}

/// Suite's affine curve point type.
pub type AffinePoint<S> = <S as Suite>::Affine;
/// Suite's base field type.
pub type BaseField<S> = <AffinePoint<S> as AffineRepr>::BaseField;
/// Suite's scalar field type.
pub type ScalarField<S> = <AffinePoint<S> as AffineRepr>::ScalarField;
/// Suite's curve configuration type.
pub type CurveConfig<S> = <AffinePoint<S> as AffineRepr>::Config;

/// Crate error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Proof verification failed.
    VerificationFailure,
    /// Invalid input data (e.g. point not in the prime-order subgroup,
    /// forbidden identity point, deserialization failure, hash-to-curve
    /// found no point).
    InvalidData,
    /// Ring capacity exceeded (requested ring size beyond the parameters
    /// capacity, SRS too short, or no free slots left in the builder).
    RingCapacityExceeded,
    /// SRS lookup failed during incremental ring construction.
    SrsLookupFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::VerificationFailure => "proof verification failed",
            Error::InvalidData => "invalid data",
            Error::RingCapacityExceeded => "ring capacity exceeded",
            Error::SrsLookupFailed => "SRS lookup failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}

impl From<ark_serialize::SerializationError> for Error {
    fn from(_err: ark_serialize::SerializationError) -> Self {
        Error::InvalidData
    }
}

/// Cipher suite: the curve, the transcript and the core operations.
///
/// The defaults follow RFC 9381 and RFC 8032, but hash with the suite
/// [`Transcript`]. A suite can override each default.
pub trait Suite: Copy {
    /// Suite identifier.
    ///
    /// It separates the transcript domains and prefixes the hash-to-curve DST.
    /// Elligator2 suites need fewer than 255 bytes (checked at compile time).
    const SUITE_ID: &'static [u8];

    /// Security level in bits.
    ///
    /// It sizes the delinearization and batch scalars, the nonce expansion and
    /// the hash-to-curve field expansion, so that each modular reduction has a
    /// bias of at most `2^-SECURITY_PARAMETER`. It also sets the default
    /// [`Self::CHALLENGE_LEN`].
    const SECURITY_PARAMETER: usize = 128;

    /// Challenge length in bytes.
    ///
    /// Defaults to `SECURITY_PARAMETER / 8`, the RFC 9381 `cLen`. The Tiny
    /// proof encodes `c` on this length. A value below the default or above the
    /// scalar field length does not compile.
    const CHALLENGE_LEN: usize = Self::SECURITY_PARAMETER / 8;

    /// Generator. Defaults to the arkworks generator.
    const GENERATOR: AffinePoint<Self> = <Self::Affine as AffineRepr>::GENERATOR;

    /// Affine curve point.
    ///
    /// The type allows any curve point. See [`PointWrapper`] for where
    /// subgroup membership is checked.
    type Affine: AffineRepr<Group: utils::ProjectiveZ>;

    /// Fiat-Shamir transcript.
    type Transcript: Transcript;

    /// Nonce from the secret key and the transcript.
    ///
    /// Defaults to [`utils::nonce`] (deterministic, after RFC 8032 section 5.1.6).
    #[inline(always)]
    fn nonce(sk: &ScalarField<Self>, transcript: Self::Transcript) -> ScalarField<Self> {
        utils::nonce::<Self>(sk, transcript)
    }

    /// Challenge from curve points and the transcript.
    ///
    /// Defaults to [`utils::challenge`] (after RFC 9381 section 5.4.3), which
    /// keeps [`Self::CHALLENGE_LEN`] bytes. An override must keep the same
    /// length, because the Tiny proof encodes only these bytes.
    #[inline(always)]
    fn challenge(pts: &[&AffinePoint<Self>], transcript: Self::Transcript) -> ScalarField<Self> {
        utils::challenge::<Self>(pts, transcript)
    }

    /// Hash data to a curve point. The caller applies any salt to `data`.
    ///
    /// The point must be in the prime-order subgroup, and nobody may know its
    /// discrete log to [`Self::GENERATOR`]. [`Input::new`] and the verifiers do
    /// not check this.
    ///
    /// Defaults to [`utils::hash_to_curve_tai`] (try-and-increment).
    /// [`utils::hash_to_curve_ell2_xmd`] is the Elligator2 alternative.
    #[inline(always)]
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>> {
        utils::hash_to_curve_tai::<Self>(data)
    }

    /// Hash a curve point to `N` bytes. Defaults to [`utils::point_to_hash`].
    #[inline(always)]
    fn point_to_hash<const N: usize>(pt: &AffinePoint<Self>) -> [u8; N] {
        utils::point_to_hash::<Self, N>(pt, false)
    }
}

/// Secret key: the secret scalar and its public key.
///
/// The scalar is zeroized on drop, redacted in `Debug` and compared in constant
/// time. Key derivation and the provers zeroize their secret temporaries, but
/// not the temporaries inside arkworks and the ring proof backend. The caller
/// owns the Pedersen blinding factor (see [`pedersen::Proof::prove`]).
///
/// Scalar multiplications by the secret run in variable time, also with
/// `secret-split`.
#[derive(Clone)]
pub struct Secret<S: Suite> {
    pub(crate) scalar: ScalarField<S>,
    pub(crate) public: Public<S>,
}

impl<S: Suite> core::fmt::Debug for Secret<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secret")
            .field("scalar", &"<redacted>")
            .field("public", &self.public.0)
            .finish()
    }
}

impl<S: Suite> PartialEq for Secret<S> {
    /// Timing does not depend on the scalars content or on where they differ.
    fn eq(&self, other: &Self) -> bool {
        let mut lhs = self.scalar.into_bigint();
        let mut rhs = other.scalar.into_bigint();
        let diff = lhs
            .as_ref()
            .iter()
            .zip(rhs.as_ref())
            .fold(0u64, |acc, (a, b)| acc | (a ^ b));
        lhs.as_mut().zeroize();
        rhs.as_mut().zeroize();
        diff == 0
    }
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
        let public = Public::from_affine_unchecked(smul!(S::GENERATOR, scalar).into_affine());
        Self { scalar, public }
    }

    /// Derive a `Secret` from a seed with the suite transcript.
    ///
    /// The scalar is in `[1, n - 1]`, with no clamping and no cofactor
    /// multiplication.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let mut cnt = 0_u8;
        let mut sk = ScalarField::<S>::from_le_bytes_mod_order(&seed);
        let scalar = loop {
            let mut transcript = S::Transcript::new(S::SUITE_ID);
            transcript.absorb_raw(&seed);
            if cnt > 0 {
                transcript.absorb_raw(&[cnt]);
            }
            let scalar = utils::nonce::<S>(&sk, transcript);
            if !scalar.is_zero() {
                break scalar;
            }
            cnt = cnt
                .checked_add(1)
                .expect("unreachable: transcript hash produced 256 consecutive zero scalars");
        };
        seed.zeroize();
        sk.zeroize();
        Self::from_scalar(scalar)
    }

    /// Random `Secret` from `rng`.
    pub fn from_rand(rng: &mut impl ark_std::rand::RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let secret = Self::from_seed(seed);
        seed.zeroize();
        secret
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
        Output::from_affine_unchecked(smul!(input.0, self.scalar).into_affine())
    }

    /// Get the VRF input-output pair relative to input.
    pub fn vrf_io(&self, input: Input<S>) -> VrfIo<S> {
        VrfIo {
            input,
            output: self.output(input),
        }
    }
}

/// Curve point with a role `K`: [`Public`], [`Input`] or [`Output`].
///
/// # Validation
///
/// [`Public`] and [`Output`] come from [`PointWrapper::from_affine`] or from
/// deserialization. [`Input`] comes only from [`Input::new`].
///
/// `from_affine` and the checked decoders (`deserialize_*`) accept only points
/// in the prime-order subgroup, and reject the identity. The verifiers depend
/// on this: they reject the identity, but they do not check subgroup membership
/// again. The unchecked decoders (`deserialize_*_unchecked`) do no validation,
/// so the caller must do it. The same rules apply to the points in the proofs.
///
/// Each value has one accepted encoding. The decoders do not reject trailing
/// bytes; [`CanonicalDeserializeExact`] does.
#[derive(Debug, Clone, Copy)]
pub struct PointWrapper<S: Suite, K>(pub(crate) AffinePoint<S>, PhantomData<K>);

// Not derived: the derive would require `S: PartialEq` of the suite marker.
impl<S: Suite, K> PartialEq for PointWrapper<S, K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: Suite, K> Eq for PointWrapper<S, K> {}

/// Role marker of [`Public`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKind;

/// Role marker of [`Input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputKind;

/// Role marker of [`Output`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputKind;

mod sealed {
    pub trait Sealed {}
}

/// Role markers of the points that serialize. [`InputKind`] is left out, see
/// [`Input`]. The trait is sealed: other crates cannot implement it.
pub trait Serializable: sealed::Sealed + Sync {}

impl sealed::Sealed for PublicKind {}

impl Serializable for PublicKind {}

impl sealed::Sealed for OutputKind {}

impl Serializable for OutputKind {}

/// Public key.
pub type Public<S> = PointWrapper<S, PublicKind>;

/// VRF input point.
///
/// Build it with [`Input::new`] from the input data, on both sides. `Input` has
/// no `from_affine` and no decoder, so a verifier cannot take a point that the
/// prover chose (see the crate "Security" section).
pub type Input<S> = PointWrapper<S, InputKind>;

/// VRF output point.
pub type Output<S> = PointWrapper<S, OutputKind>;

impl<S: Suite, K: Sync> ark_serialize::Valid for PointWrapper<S, K> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        if self.is_identity() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        self.0.check()
    }
}

impl<S: Suite, K: Serializable> CanonicalSerialize for PointWrapper<S, K> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl<S: Suite, K: Serializable> CanonicalDeserialize for PointWrapper<S, K> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let point = AffinePoint::<S>::deserialize_strict(reader, compress, validate)?;
        let wrapper = Self::from_affine_unchecked(point);
        // `check()` ran on the point; the identity rule remains.
        if matches!(validate, ark_serialize::Validate::Yes) && wrapper.is_identity() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(wrapper)
    }
}

impl<S: Suite, K: Sync> PointWrapper<S, K> {
    /// Wrap a point with no validation. The caller makes sure that it is valid.
    pub(crate) fn from_affine_unchecked(value: AffinePoint<S>) -> Self {
        Self(value, PhantomData)
    }

    /// Get the affine point.
    pub fn into_affine(self) -> AffinePoint<S> {
        self.0
    }

    /// Whether the point is the group identity. The verifiers reject it, also
    /// for points that did not go through a checked decoder.
    pub(crate) fn is_identity(&self) -> bool {
        self.0.is_zero()
    }
}

impl<S: Suite, K: Serializable> PointWrapper<S, K> {
    /// Wrap a point. Returns `Error::InvalidData` if the point is not in the
    /// prime-order subgroup or is the identity.
    pub fn from_affine(value: AffinePoint<S>) -> Result<Self, Error> {
        let wrapper = Self::from_affine_unchecked(value);
        ark_serialize::Valid::check(&wrapper).map_err(|_| Error::InvalidData)?;
        Ok(wrapper)
    }
}

impl<S: Suite> Input<S> {
    /// Hash `data` to an input point with [`Suite::data_to_point`].
    ///
    /// Returns `Error::InvalidData` if the map finds no point or gives the
    /// identity. Subgroup membership is not checked (see
    /// [`Suite::data_to_point`]).
    pub fn new(data: &[u8]) -> Result<Self, Error> {
        S::data_to_point(data)
            .map(Self::from_affine_unchecked)
            .filter(|input| !input.is_identity())
            .ok_or(Error::InvalidData)
    }
}

impl<S: Suite> Output<S> {
    /// Hash the output point to `N` bytes.
    pub fn hash<const N: usize>(&self) -> [u8; N] {
        S::point_to_hash(&self.0)
    }
}

/// VRF input-output pair.
///
/// The pair does not implement the serialization traits, because [`Input`]
/// does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfIo<S: Suite> {
    /// Input point, from [`Input::new`].
    pub input: Input<S>,
    /// Output point: the input times the secret scalar.
    pub output: Output<S>,
}

impl<S: Suite> AsRef<[VrfIo<S>]> for VrfIo<S> {
    fn as_ref(&self) -> &[VrfIo<S>] {
        core::slice::from_ref(self)
    }
}

impl<S: Suite> VrfIo<S> {
    /// Whether a point of the pair is the identity. The verifiers reject such a
    /// pair.
    pub(crate) fn has_identity(&self) -> bool {
        self.input.is_identity() || self.output.is_identity()
    }
}

/// Type aliases for the given suite.
#[macro_export]
macro_rules! suite_types {
    ($suite:ident) => {
        /// Secret key.
        #[allow(dead_code)]
        pub type Secret = $crate::Secret<$suite>;
        /// Public key.
        #[allow(dead_code)]
        pub type Public = $crate::Public<$suite>;
        /// VRF input point.
        #[allow(dead_code)]
        pub type Input = $crate::Input<$suite>;
        /// VRF output point.
        #[allow(dead_code)]
        pub type Output = $crate::Output<$suite>;
        /// Affine curve point.
        #[allow(dead_code)]
        pub type AffinePoint = $crate::AffinePoint<$suite>;
        /// Scalar field.
        #[allow(dead_code)]
        pub type ScalarField = $crate::ScalarField<$suite>;
        /// Base field.
        #[allow(dead_code)]
        pub type BaseField = $crate::BaseField<$suite>;
        /// Tiny VRF proof.
        #[allow(dead_code)]
        pub type TinyProof = $crate::tiny::Proof<$suite>;
        /// Pedersen VRF proof.
        #[allow(dead_code)]
        pub type PedersenProof = $crate::pedersen::Proof<$suite>;
        /// Pedersen VRF batch verification item.
        #[allow(dead_code)]
        pub type PedersenBatchItem = $crate::pedersen::BatchItem<$suite>;
        /// Pedersen VRF batch verifier.
        #[allow(dead_code)]
        pub type PedersenBatchVerifier = $crate::pedersen::BatchVerifier<$suite>;
        /// Thin VRF proof.
        #[allow(dead_code)]
        pub type ThinProof = $crate::thin::Proof<$suite>;
        /// Thin VRF batch verification item.
        #[allow(dead_code)]
        pub type ThinBatchItem = $crate::thin::BatchItem<$suite>;
        /// Thin VRF batch verifier.
        #[allow(dead_code)]
        pub type ThinBatchVerifier = $crate::thin::BatchVerifier<$suite>;
        /// VRF input-output pair.
        #[allow(dead_code)]
        pub type VrfIo = $crate::VrfIo<$suite>;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use suites::testing::{Input, Secret, TestSuite};
    use testing::{TEST_SEED, random_val};

    #[test]
    fn vrf_output_check() {
        use ark_std::rand::SeedableRng;
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([42; 32]);
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(Some(&mut rng)));
        let output = secret.output(input);

        let expected = "4af9bf572a107a8f61faa380667efe27eaf399cc8e718d57ef328924eb51d450";
        assert_eq!(expected, hex::encode(output.hash::<32>()));
    }

    /// One `{:?}` on a secret in a downstream log must not leak the key.
    #[test]
    fn secret_debug_redacts_scalar() {
        let secret = Secret::from_seed(TEST_SEED);
        let out = std::format!("{:?}", secret);
        let scalar_str = std::format!("{:?}", secret.scalar());
        assert!(!out.contains(&scalar_str));
    }

    /// Equality semantics must survive the switch to the constant-time impl.
    #[test]
    fn secret_partial_eq() {
        let secret = Secret::from_seed(TEST_SEED);
        assert_eq!(secret, Secret::from_seed(TEST_SEED));
        assert_ne!(secret, Secret::from_seed([0xff; 32]));
    }

    /// Downstream code compares `Error` values and puts them in `dyn Error`
    /// chains. The messages are not part of the contract.
    #[test]
    fn error_type_ergonomics() {
        let err: &dyn core::error::Error = &Error::VerificationFailure;
        assert!(!err.to_string().is_empty());
        assert_eq!(
            Error::from(ark_serialize::SerializationError::InvalidData),
            Error::InvalidData
        );
        assert_ne!(Error::InvalidData, Error::RingCapacityExceeded);
    }

    /// `Input::new` must work with `?`, and a map that finds no point must give
    /// `Error::InvalidData`.
    #[test]
    fn input_new_returns_crate_error() {
        #[derive(Debug, Copy, Clone)]
        struct NeverSuite;

        impl Suite for NeverSuite {
            const SUITE_ID: &'static [u8] = b"Never";
            type Affine = <TestSuite as Suite>::Affine;
            type Transcript = <TestSuite as Suite>::Transcript;

            fn data_to_point(_data: &[u8]) -> Option<AffinePoint<Self>> {
                None
            }
        }

        fn build() -> Result<Input, Error> {
            let input = Input::new(b"data")?;
            Ok(input)
        }
        assert!(build().is_ok());
        assert_eq!(
            crate::Input::<NeverSuite>::new(b"data").unwrap_err(),
            Error::InvalidData
        );
    }

    /// The wrapper has no `Deref`, so the roles stay distinct. `into_affine` is
    /// the only way to read the point.
    #[test]
    fn point_wrapper_point_accessor() {
        let public = Secret::from_seed(TEST_SEED).public();
        assert_eq!(public.into_affine(), public.0);
    }

    /// The subgroup check accepts the identity. Its secret key is zero, so the
    /// checked decoder must reject it on its own.
    #[test]
    fn identity_public_key_construction_rejected() {
        type S = TestSuite;

        let identity = AffinePoint::<S>::zero();
        assert!(ark_serialize::Valid::check(&identity).is_ok());

        let mut buf = Vec::new();
        identity.serialize_compressed(&mut buf).unwrap();
        assert!(crate::Public::<S>::deserialize_compressed(&buf[..]).is_err());

        // Unchecked paths are documented as skipping validation.
        assert!(crate::Public::<S>::deserialize_compressed_unchecked(&buf[..]).is_ok());
        assert!(crate::Public::<S>::from_affine_unchecked(identity).is_identity());
    }

    /// The pair `(0, 0)` satisfies `O = x * I` for every key and passes the
    /// subgroup check, so the checked decoder must reject it on its own.
    #[test]
    fn identity_io_point_construction_rejected() {
        type S = TestSuite;

        let identity = AffinePoint::<S>::zero();

        let mut buf = Vec::new();
        identity.serialize_compressed(&mut buf).unwrap();
        assert!(crate::Output::<S>::deserialize_compressed(&buf[..]).is_err());

        // Unchecked paths are documented as skipping validation.
        assert!(crate::Output::<S>::deserialize_compressed_unchecked(&buf[..]).is_ok());
        assert!(crate::Input::<S>::from_affine_unchecked(identity).is_identity());
        assert!(crate::Output::<S>::from_affine_unchecked(identity).is_identity());
    }

    /// An unchecked output `O + L`, with `L` of order 2, verifies for some `ad`
    /// and hashes to another VRF output. Only the subgroup check of the
    /// decoders stops it.
    #[test]
    fn prove_uniqueness_vulnerability() {
        use ark_ff::BigInteger;
        use ark_std::{One, Zero};
        use utils::common::DomSep;

        type S = TestSuite;
        type Sc = ScalarField<S>;

        let secret = crate::Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::new(b"uniqueness attack").unwrap();
        let honest_output = secret.output(input);

        // (0, -1) has order 2 on Ed25519.
        let low_order_pt =
            AffinePoint::<S>::new_unchecked(BaseField::<S>::zero(), -BaseField::<S>::one());
        assert!(!low_order_pt.is_zero());
        assert!((low_order_pt.into_group() + low_order_pt.into_group()).is_zero());

        let malicious_output =
            Output::from_affine_unchecked((honest_output.0 + low_order_pt).into_affine());
        assert_ne!(honest_output, malicious_output);
        assert_ne!(honest_output.hash::<32>(), malicious_output.hash::<32>());

        // The forgery verifies when `c * z_1 * L = 0`. Find an `ad` that gives
        // an even `z_1`, then grind `k` for an odd `c`.
        let malicious_io = VrfIo {
            input,
            output: malicious_output,
        };
        let mal_ios = [malicious_io];

        let mut ad_ctr = 0u32;
        let (ad, t, merged_input) = loop {
            let ad = format!("ad-{ad_ctr}");
            let (t, zs) = utils::vrf_transcript_scalars_with_schnorr(
                DomSep::TinyVrf,
                public.0,
                mal_ios,
                ad.as_bytes(),
            );
            if zs[1].into_bigint().is_even() {
                let i_m = (S::GENERATOR * zs[0] + input.0 * zs[1]).into_affine();
                break (ad, t, i_m);
            }
            ad_ctr += 1;
            assert!(ad_ctr < 100, "Failed to find suitable ad");
        };

        // An odd `c` makes `q - c` even, so `(-c) * L = 0`.
        let mut ctr = 0u64;
        let proof = loop {
            let mut k_seed = [0u8; 8];
            k_seed.copy_from_slice(&ctr.to_le_bytes());
            let k = Sc::from_le_bytes_mod_order(&k_seed);
            let r = (merged_input * k).into_affine();

            let c = S::challenge(&[&r], t.clone());

            if !c.into_bigint().is_even() {
                let s = k + c * secret.scalar;
                break crate::tiny::Proof { c, s };
            }
            ctr += 1;
            assert!(ctr <= 1000, "Grinding failed");
        };

        assert!(
            public
                .verify_tiny(malicious_io, ad.as_bytes(), &proof)
                .is_ok()
        );

        let honest_io = VrfIo {
            input,
            output: honest_output,
        };
        let honest_proof = secret.prove_tiny(honest_io, ad.as_bytes());
        assert!(
            public
                .verify_tiny(honest_io, ad.as_bytes(), &honest_proof)
                .is_ok()
        );

        // Two different outputs for the same input and public key.
        assert_ne!(honest_output.hash::<32>(), malicious_output.hash::<32>());
    }
}
