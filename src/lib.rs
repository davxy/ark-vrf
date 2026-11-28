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
//! let secret = SecretKey::from_seed([0; 32]);
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
//! - `secret-split`: each secret scalar multiplication uses two random shares
//!   of the scalar, against side channels, at twice the cost. The timing stays
//!   variable. The ring proof backend does not use the split.
//! - `hedged-nonce`: the default nonce ([`Suite::nonce`]) also absorbs 32
//!   random bytes. Then two Pedersen or Ring proofs with no I/O pairs on the
//!   same additional data are not linkable.
//! - `ring`: Ring VRF for the curves that support it.
//! - `shake128`: `Shake128Transcript` and the `bandersnatch_shake128` suite.
//!
//! `secret-split` and `hedged-nonce` panic when the system random source fails.
//! On some `no_std` targets, the application must select a `getrandom` backend.
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

pub use utils::canonical::CanonicalDeserializeExact;
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

mod point;
mod secret;

pub use point::{
    Input, InputKind, IoPair, Output, OutputKind, PointWrapper, PublicKey, PublicKeyKind,
    Serializable,
};
pub use secret::{SecretKey, SecretScalar};

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
    /// Defaults to [`utils::nonce`] (deterministic, after RFC 8032 section 5.1.6),
    /// or to `utils::hedged_nonce` with the `hedged-nonce` feature.
    #[inline(always)]
    fn nonce(sk: &SecretScalar<Self>, transcript: Self::Transcript) -> SecretScalar<Self> {
        #[cfg(feature = "hedged-nonce")]
        return utils::hedged_nonce::<Self>(sk, transcript);
        #[cfg(not(feature = "hedged-nonce"))]
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

/// Type aliases for the given suite.
#[macro_export]
macro_rules! suite_types {
    ($suite:ident) => {
        /// Secret key.
        #[allow(dead_code)]
        pub type SecretKey = $crate::SecretKey<$suite>;
        /// Public key.
        #[allow(dead_code)]
        pub type PublicKey = $crate::PublicKey<$suite>;
        /// Secret scalar.
        #[allow(dead_code)]
        pub type SecretScalar = $crate::SecretScalar<$suite>;
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
        pub type IoPair = $crate::IoPair<$suite>;
    };
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
