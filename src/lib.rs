//! # Elliptic Curve VRF
//!
//! Implementations of Verifiable Random Function with Additional Data (VRF-AD)
//! schemes built on a transcript-based Fiat-Shamir transform with support for
//! multiple input/output pairs via delinearization.
//!
//! Built on the [Arkworks](https://github.com/arkworks-rs) framework with
//! configurable cryptographic parameters and `no_std` support.
//!
//! ## Security
//!
//! VRF input points **must** be constructed via hash-to-curve (e.g.
//! [`Input::new`]) so that nobody knows their discrete-log relation to the
//! generator `G`. If the prover knew such a relation, they could forge
//! outputs. This is critical because the delinearization merges the Schnorr
//! and VRF pairs into a single check.
//!
//! ## Schemes
//!
//! - **Tiny VRF**: Compact proof. Loosely inspired by
//!   [RFC-9381](https://datatracker.ietf.org/doc/rfc9381), adapted with a
//!   transcript-based Fiat-Shamir transform, support for additional data, and
//!   multiple I/O pairs via delinearization.
//!
//! - **Thin VRF**: Same structure as Tiny VRF but stores the nonce commitment
//!   instead of the challenge, enabling batch verification at the cost of a
//!   slightly larger proof.
//!
//! - **Pedersen VRF**: Key-hiding VRF based on the construction introduced by
//!   [BCHSV23](https://eprint.iacr.org/2023/002). Replaces the public key with a
//!   Pedersen commitment to the secret key, serving as a building block for
//!   anonymized ring signatures.
//!
//! - **Ring VRF**: Anonymized ring VRF combining Pedersen VRF with the ring proof
//!   scheme derived from [CSSV22](https://eprint.iacr.org/2022/1205). Proves that
//!   a single blinded key is a member of a committed ring without revealing which one.
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
//! - **Ed25519**: Supports Tiny, Thin, and Pedersen VRF.
//! - **Secp256r1**: Supports Tiny, Thin, and Pedersen VRF.
//! - **Bandersnatch** (_Edwards curve on BLS12-381_): Supports Tiny, Thin, Pedersen, and Ring VRF.
//! - **JubJub** (_Edwards curve on BLS12-381_): Supports Tiny, Thin, Pedersen, and Ring VRF.
//! - **Baby-JubJub** (_Edwards curve on BN254_): Supports Tiny, Thin, Pedersen, and Ring VRF.
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
//! - `full`: All the curves below plus `ring`.
//! - `secret-split`: Split-secret scalar multiplication. Secret scalar is split into the sum
//!   of two scalars, which randomly mutate but retain the same sum. Incurs 2x penalty in the
//!   secret scalar multiplications of the Tiny, Thin and Pedersen VRFs (public key
//!   derivation, output, nonce and blinding), but provides side channel defenses for them.
//!   The split draws from `OsRng` on every secret scalar multiplication, `Secret`
//!   deserialization included. The feature is `no_std`. It enables
//!   `rand/getrandom`, so the application must give `getrandom` a backend where
//!   it has none: `getrandom/js` on `wasm32-unknown-unknown`, `getrandom/custom`
//!   or `getrandom/rdrand` on bare metal. `OsRng` panics where the backend fails
//!   at run time.
//!   The multiplication stays variable time with the feature and without it.
//!   Ring proof witness generation is not covered by this feature: it relies on the
//!   branch-free handling of the secret bits
//!   implemented in the `w3f-ring-proof` and `w3f-plonk-common` crates.
//! - `ring`: Ring-VRF for the curves supporting it.
//! - `shake128`: `Shake128Transcript` and the `bandersnatch_shake128` suite.
//! - `print-trace`: Forwards to `ark-std/print-trace`. The ring proof backend prints
//!   the timers of its phases.
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
#![cfg_attr(not(test), warn(missing_docs))]

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::marker::PhantomData;

use utils::canonical::deserialize_point;
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

/// Defines a cipher suite.
///
/// Configures the elliptic curve, transcript, and core operations (nonce
/// generation, challenge derivation, hash-to-curve) for a VRF-AD scheme.
/// The default implementations are inspired by RFC-9381 and RFC-8032 but
/// use a pluggable [`Transcript`]-based Fiat-Shamir transform rather than
/// the specific hash constructions prescribed by the RFC. Default methods
/// can be overridden to implement custom VRF variants.
pub trait Suite: Copy {
    /// Suite identifier.
    ///
    /// A unique byte string used for transcript domain separation and as the
    /// hash-to-curve DST prefix. The actual constructions a `SUITE_ID` stands
    /// for are defined by the suite specification (see each suite's module
    /// docs). Implementations targeting interop must use the same string.
    /// Suites that hash to curve with Elligator2 need fewer than 255 bytes,
    /// checked at compile time.
    const SUITE_ID: &'static [u8];

    /// Security level in bits.
    ///
    /// Sizes the delinearization and batch verification scalars, the nonce
    /// expansion and the hash-to-curve field expansion, so that each modular
    /// reduction has a bias of at most `2^-SECURITY_PARAMETER`, and the
    /// default of [`Self::CHALLENGE_LEN`]. The built-in suites use the default.
    const SECURITY_PARAMETER: usize = 128;

    /// Challenge length in bytes.
    ///
    /// Defaults to [`Self::SECURITY_PARAMETER`] over eight, the RFC 9381
    /// `cLen`. A suite may set a wider challenge, up to the scalar field byte
    /// length, for a tighter Fiat-Shamir bound; the Tiny proof encodes `c` on
    /// this length. A challenge shorter than the level, or wider than the
    /// scalar field, does not compile.
    const CHALLENGE_LEN: usize = Self::SECURITY_PARAMETER / 8;

    /// Curve point in affine representation.
    ///
    /// The `AffineRepr` bound does not guarantee prime-order subgroup
    /// membership: a value of this type may be any point on the curve. The
    /// [`PointWrapper`] checked paths enforce membership.
    type Affine: AffineRepr;

    /// Fiat-Shamir transcript.
    ///
    /// Provides absorb/squeeze interface for challenge generation,
    /// nonce derivation, delinearization, and other hash-based operations.
    type Transcript: Transcript;

    /// Generator used through all the suite.
    ///
    /// Defaults to Arkworks provided generator.
    #[inline(always)]
    fn generator() -> AffinePoint<Self> {
        Self::Affine::generator()
    }

    /// Generate a nonce scalar from the secret key and transcript state.
    ///
    /// The transcript typically carries shared state from `vrf_transcript`,
    /// binding the nonce to the I/O pairs and additional data.
    ///
    /// Defaults to [`utils::nonce`] (deterministic, inspired by RFC-8032 section 5.1.6).
    #[inline(always)]
    fn nonce(sk: &ScalarField<Self>, transcript: Self::Transcript) -> ScalarField<Self> {
        utils::nonce::<Self>(sk, transcript)
    }

    /// Derive a challenge scalar from curve points and transcript state.
    ///
    /// Absorbs curve points into the transcript and squeezes a scalar.
    /// The transcript typically carries shared state from `vrf_transcript`.
    /// The default takes [`Self::CHALLENGE_LEN`] bytes of the squeeze, the
    /// RFC 9381 `cLen`, so the challenge carries that many bytes inside a
    /// full scalar. The Tiny proof encodes those bytes only, so an override
    /// must truncate the same way.
    ///
    /// Defaults to [`utils::challenge`] (inspired by RFC-9381 section 5.4.3).
    #[inline(always)]
    fn challenge(pts: &[&AffinePoint<Self>], transcript: Self::Transcript) -> ScalarField<Self> {
        utils::challenge::<Self>(pts, transcript)
    }

    /// Hash data to a curve point.
    ///
    /// The input `data` is the raw pre-image; any salting must be applied
    /// by the caller before invoking this method.
    ///
    /// Defaults to [`utils::hash_to_curve_tai`] (try-and-increment).
    /// Override for alternative methods like [`utils::hash_to_curve_ell2_xmd`] (Elligator2).
    #[inline(always)]
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>> {
        utils::hash_to_curve_tai::<Self>(data)
    }

    /// Map a curve point to a hash value.
    ///
    /// Defaults to [`utils::point_to_hash`].
    #[inline(always)]
    fn point_to_hash<const N: usize>(pt: &AffinePoint<Self>) -> [u8; N] {
        utils::point_to_hash::<Self, N>(pt, false)
    }
}

/// Secret key for VRF operations.
///
/// Contains the private scalar and cached public key.
/// Implements automatic zeroization on drop. The `Debug` output redacts
/// the scalar, and equality is evaluated in constant time. Key derivation
/// and the provers zeroize their secret temporaries: seeds, nonces, the
/// challenge products and, with `secret-split`, the split scalars. This is
/// best effort: temporaries inside arkworks and the ring proof backend are
/// not wiped. The Pedersen prover returns the blinding factor to the caller,
/// who owns it from then on (see [`pedersen::Proof::prove`]).
///
/// Scalar multiplications over the secret run in variable time: the arkworks
/// double-and-add loop follows the bits of the scalar. `secret-split` hides
/// the value of the scalar, not the timing.
#[derive(Clone)]
pub struct Secret<S: Suite> {
    /// Secret scalar.
    pub(crate) scalar: ScalarField<S>,
    /// Cached public key.
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
        let public = Public::from_affine_unchecked(smul!(S::generator(), scalar).into_affine());
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
            // Reaching 256 consecutive zero scalars is unreachable under
            // standard assumptions on the transcript hash (probability
            // ≈ 2^(-65000)); hitting it implies a broken primitive.
            cnt = cnt
                .checked_add(1)
                .expect("unreachable: transcript hash produced 256 consecutive zero scalars");
        };
        seed.zeroize();
        sk.zeroize();
        Self::from_scalar(scalar)
    }

    /// Construct an ephemeral `Secret` using the provided randomness source.
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

/// Curve point wrapper generic over the cipher suite and the point role `K`.
///
/// [`Public`], [`Input`] and [`Output`] are instances of this type with
/// distinct role markers, so they share one implementation but remain
/// distinct types.
///
/// # Validation
///
/// [`Self::from_affine`] and the checked deserialization methods (the default
/// `deserialize_*` family, for [`Public`] and [`Output`]) accept only points
/// in the prime-order subgroup and reject the group identity. The verifiers
/// trust this invariant: they reject the identity, which is cheap, but they
/// do not repeat the subgroup check. [`Self::from_affine_unchecked`] and the
/// `deserialize_*_unchecked` methods skip validation and leave this
/// responsibility to the caller. Both paths accept one encoding per point
/// and do not reject trailing bytes.
///
/// [`Self::point`] reads the affine point.
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

/// Role markers of the points that serialize. [`InputKind`] is left out, see
/// [`Input`].
pub(crate) trait Serializable: Sync {}

impl Serializable for PublicKind {}

impl Serializable for OutputKind {}

/// Public key generic over the cipher suite.
///
/// Elliptic curve point representing the public component of a VRF key pair.
pub type Public<S> = PointWrapper<S, PublicKind>;

/// VRF input point generic over the cipher suite.
///
/// Elliptic curve point representing the VRF input. Construct it with
/// [`Input::new`], which applies hash-to-curve. [`PointWrapper::from_affine`]
/// validates subgroup membership only: the caller must still ensure the point
/// is not in a known discrete-log relation with the suite generator, which the
/// soundness of the schemes requires (see the crate docs).
///
/// `Input` does not implement the serialization traits, so a verifier cannot
/// take a prover-chosen point. Send the input data and call [`Input::new`] on
/// both sides.
pub type Input<S> = PointWrapper<S, InputKind>;

/// VRF output point generic over the cipher suite.
///
/// Elliptic curve point representing the VRF output.
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
        let point = deserialize_point::<S>(reader, compress, validate)?;
        let wrapper = Self::from_affine_unchecked(point);
        // `check()` ran on the point; the identity rule remains.
        if matches!(validate, ark_serialize::Validate::Yes) && wrapper.is_identity() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(wrapper)
    }
}

impl<S: Suite, K: Sync> PointWrapper<S, K> {
    /// Construct from an affine point with validation.
    ///
    /// Returns `Error::InvalidData` if the point is not in the prime-order
    /// subgroup or is the group identity.
    pub fn from_affine(value: AffinePoint<S>) -> Result<Self, Error> {
        let wrapper = Self::from_affine_unchecked(value);
        ark_serialize::Valid::check(&wrapper).map_err(|_| Error::InvalidData)?;
        Ok(wrapper)
    }

    /// Construct from an affine point without validation.
    ///
    /// The caller must ensure `value` is in the prime-order subgroup and is not
    /// the group identity. The verifiers do not repeat these checks.
    pub fn from_affine_unchecked(value: AffinePoint<S>) -> Self {
        Self(value, PhantomData)
    }

    /// Get the affine point.
    pub fn point(&self) -> AffinePoint<S> {
        self.0
    }

    /// Whether the point is the group identity.
    ///
    /// The identity passes the subgroup check but is never a usable point: as a
    /// key its secret scalar is zero, and an I/O pair holding it satisfies
    /// `O = x * I` for every `x`. Verifiers reject it explicitly rather than
    /// relying on the caller having gone through a checked constructor.
    pub(crate) fn is_identity(&self) -> bool {
        self.0.is_zero()
    }
}

impl<S: Suite> Input<S> {
    /// Construct from [`Suite::data_to_point`].
    ///
    /// Maps arbitrary data to a curve point via hash-to-curve. Returns
    /// `Error::InvalidData` if no point is found.
    pub fn new(data: &[u8]) -> Result<Self, Error> {
        S::data_to_point(data)
            .map(Self::from_affine_unchecked)
            .ok_or(Error::InvalidData)
    }
}

impl<S: Suite> Output<S> {
    /// Hash the output point to a deterministic byte string.
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
    /// Whether either point of the pair is the group identity.
    ///
    /// Such a pair is satisfied by every secret key, so it binds its VRF output
    /// to no signer. Verifiers reject it before evaluating their equations.
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

    /// `Error` must stay usable downstream: kinds comparable in tests, and
    /// values convertible into `dyn Error` chains (`anyhow`, `thiserror`).
    /// The exact messages are not part of the contract; the impls are.
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

    /// `Input::new` must compose with `?` in functions returning the crate
    /// error, like the other checked constructors. A suite whose hash-to-curve
    /// finds no point must surface that as `Error::InvalidData`.
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

    /// The wrapper does not dereference to the affine point. `point()` is the
    /// one read path, so the role types stay distinct.
    #[test]
    fn point_wrapper_point_accessor() {
        let public = Secret::from_seed(TEST_SEED).public();
        assert_eq!(public.point(), public.0);
    }

    /// The identity is a well-formed subgroup element, so the subgroup check
    /// alone lets it through. It must be rejected on every checked path, since
    /// its secret scalar is zero and hence known to anybody.
    #[test]
    fn identity_public_key_construction_rejected() {
        type S = TestSuite;

        let identity = AffinePoint::<S>::zero();
        assert!(ark_serialize::Valid::check(&identity).is_ok());
        assert!(crate::Public::<S>::from_affine(identity).is_err());

        let mut buf = Vec::new();
        identity.serialize_compressed(&mut buf).unwrap();
        assert!(crate::Public::<S>::deserialize_compressed(&buf[..]).is_err());

        // Unchecked paths are documented as skipping validation.
        assert!(crate::Public::<S>::deserialize_compressed_unchecked(&buf[..]).is_ok());
        assert!(crate::Public::<S>::from_affine_unchecked(identity).is_identity());
    }

    /// The pair `(I, O) = (0, 0)` satisfies `O = x * I` for every secret key,
    /// so it binds a VRF output to no key at all. Like the identity public key
    /// it passes the subgroup check, so the checked constructors must reject it
    /// on their own.
    #[test]
    fn identity_io_point_construction_rejected() {
        type S = TestSuite;

        let identity = AffinePoint::<S>::zero();

        assert!(crate::Input::<S>::from_affine(identity).is_err());
        assert!(crate::Output::<S>::from_affine(identity).is_err());

        let mut buf = Vec::new();
        identity.serialize_compressed(&mut buf).unwrap();
        assert!(crate::Output::<S>::deserialize_compressed(&buf[..]).is_err());

        // Unchecked paths are documented as skipping validation.
        assert!(crate::Output::<S>::deserialize_compressed_unchecked(&buf[..]).is_ok());
        assert!(crate::Input::<S>::from_affine_unchecked(identity).is_identity());
        assert!(crate::Output::<S>::from_affine_unchecked(identity).is_identity());
    }

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

        // 1. Find a low-order point L (order 2 for Ed25519)
        // For Ed25519, (0, -1) is order 2.
        let low_order_pt =
            AffinePoint::<S>::new_unchecked(BaseField::<S>::zero(), -BaseField::<S>::one());
        assert!(!low_order_pt.is_zero());
        // Verify it's order 2: 2 * L = O
        assert!((low_order_pt.into_group() + low_order_pt.into_group()).is_zero());

        // 2. Compute gamma' = gamma + L
        let malicious_output =
            Output::from_affine_unchecked((honest_output.0 + low_order_pt).into_affine());
        assert_ne!(honest_output, malicious_output);
        assert_ne!(honest_output.hash::<32>(), malicious_output.hash::<32>());

        // 3. Forge a proof by grinding k until c*z_1 is even (so c*z_1*L = 0)
        //
        // The verify equation for the VRF I/O part is s*I_m - c*O_m = k*I_m,
        // where O_m includes z_1*(O_honest + L). For this to hold we need
        // c*z_1*L = 0, i.e. c*z_1 must be even (since L has order 2).
        // Since c is odd (ground below) we also need z_1 to be even.
        // z_1 is the delinearization scalar determined by (pk, ios, ad), so
        // we iterate over ad values to find one where z_1 is even.
        let malicious_io = VrfIo {
            input,
            output: malicious_output,
        };
        let mal_ios = [malicious_io];

        // Search for an ad that produces an even delinearization scalar z_1.
        let mut ad_ctr = 0u32;
        let (ad, t, merged_input) = loop {
            let ad = format!("ad-{ad_ctr}");
            let (t, zs) = utils::vrf_transcript_scalars_with_schnorr(
                DomSep::TinyVrf,
                public.0,
                mal_ios,
                ad.as_bytes(),
            );
            // z_1 is the delinearization scalar for the VRF pair
            if zs[1].into_bigint().is_even() {
                // Compute merged input: I_m = z_0*G + z_1*I
                let i_m = (S::generator() * zs[0] + input.0 * zs[1]).into_affine();
                break (ad, t, i_m);
            }
            ad_ctr += 1;
            assert!(ad_ctr < 100, "Failed to find suitable ad");
        };

        // Now grind k to get an odd challenge c (so that q-c is even, i.e. (-c)*L = 0).
        let mut ctr = 0u64;
        let proof = loop {
            let mut k_seed = [0u8; 8];
            k_seed.copy_from_slice(&ctr.to_le_bytes());
            let k = Sc::from_le_bytes_mod_order(&k_seed);

            // R = k * I_m (merged input including Schnorr pair)
            let r = (merged_input * k).into_affine();

            let c = S::challenge(&[&r], t.clone());

            if !c.into_bigint().is_even() {
                let s = k + c * secret.scalar;
                break crate::tiny::Proof { c, s };
            }
            ctr += 1;
            assert!(ctr <= 1000, "Grinding failed");
        };

        // 4. Verify the malicious proof
        assert!(
            public
                .verify_tiny(malicious_io, ad.as_bytes(), &proof)
                .is_ok()
        );

        // 5. Verify the honest proof still works
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
