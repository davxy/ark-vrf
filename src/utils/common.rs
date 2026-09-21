//! Common cryptographic utility functions.
//!
//! This module provides implementations of various cryptographic operations
//! used throughout the VRF schemes, including challenge generation, nonce
//! derivation, and delinearization.

use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Stack buffer size for small serialized objects (compressed points, scalars).
pub(crate) const STACK_BUF_SIZE: usize = 128;

/// Declare a zeroed `[u8; STACK_BUF_SIZE]` array and bind `$name` to a
/// `&mut [u8]` slice of the first `$len` bytes.
///
/// Intended for small serialized objects such as single compressed points
/// or scalar field elements. Panics if `$len > STACK_BUF_SIZE`.
macro_rules! stack_buf {
    ($name:ident, $len:expr) => {
        let _sb_len: usize = $len;
        let _sb_cap = $crate::utils::common::STACK_BUF_SIZE;
        assert!(
            _sb_len <= _sb_cap,
            "requested {_sb_len} bytes exceeds STACK_BUF_SIZE ({_sb_cap})"
        );
        let mut _sb_backing = [0u8; $crate::utils::common::STACK_BUF_SIZE];
        let $name = &mut _sb_backing[.._sb_len];
    };
}
pub(crate) use stack_buf;

/// Number of bytes to squeeze for an unbiased scalar via `from_le_bytes_mod_order`.
///
/// Returns `ceil((ceil(log2(p)) + SECURITY_PARAMETER) / 8)` where `p` is the
/// scalar field modulus. The extra padding keeps the bias from modular
/// reduction at most `2^-SECURITY_PARAMETER`.
///
/// See sections 5.1 and 5.3 of the
/// [IETF hash-to-curve draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/).
pub const fn expanded_scalar_len<S: Suite>() -> usize {
    let base_field_size_in_bits = ScalarField::<S>::MODULUS_BIT_SIZE as usize;
    (base_field_size_in_bits + S::SECURITY_PARAMETER).div_ceil(8)
}

pub fn nonce_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    stack_buf!(buf, expanded_scalar_len::<S>());
    t.squeeze_raw(buf);
    let scalar = ScalarField::<S>::from_le_bytes_mod_order(buf);
    buf.zeroize();
    scalar
}

/// Squeeze the challenge: [`Suite::CHALLENGE_LEN`] bytes, at least the
/// security level, reduced into a scalar.
pub fn challenge_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    const {
        assert!(
            8 * S::CHALLENGE_LEN >= S::SECURITY_PARAMETER,
            "Suite::CHALLENGE_LEN is shorter than the security level"
        )
    };
    stack_buf!(buf, S::CHALLENGE_LEN);
    t.squeeze_raw(buf);
    ScalarField::<S>::from_le_bytes_mod_order(buf)
}

/// Squeeze a random weight of [`Suite::SECURITY_PARAMETER`] bits, for the
/// delinearization scalars and the batch verification weights.
pub(crate) fn weight_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    stack_buf!(buf, S::SECURITY_PARAMETER / 8);
    t.squeeze_raw(buf);
    ScalarField::<S>::from_le_bytes_mod_order(buf)
}

/// Internal domain separation tags for protocol hashing.
///
/// Each variant is absorbed as a single byte after `SUITE_ID` to make every
/// distinct hashing context produce independent transcript states. Values are
/// grouped by purpose in blocks of sixteen.
#[repr(u8)]
pub(crate) enum DomSep {
    /// Tiny VRF scheme tag.
    TinyVrf = 0x00,
    /// Thin VRF scheme tag.
    ThinVrf = 0x01,
    /// Pedersen VRF scheme tag.
    PedersenVrf = 0x02,
    /// Nonce expansion.
    NonceExpand = 0x10,
    /// Deterministic nonce derivation from the expanded secret and transcript.
    Nonce = 0x11,
    /// Pedersen blinding scalar derivation.
    PedersenBlinding = 0x12,
    /// Point-to-hash output derivation.
    PointToHash = 0x20,
    /// Per-I/O delinearization scalar stream for multi-input proofs.
    Delinearize = 0x30,
    /// Schnorr challenge scalar derivation.
    Challenge = 0x40,
    /// Batch verification randomization scalar.
    BatchVerify = 0x50,
    /// Hash-to-curve operation.
    HashToCurve = 0x60,
}

/// I/O pairs fed to a VRF transcript: an optional Schnorr pair `(G, Y)`
/// followed by the user pairs.
///
/// Tiny and Thin VRF prepend the Schnorr pair, so the public key DLEQ
/// relation is folded into the delinearized I/O pairs.
#[derive(Clone, Copy)]
struct Ios<'a, S: Suite> {
    schnorr: Option<VrfIo<S>>,
    user: &'a [VrfIo<S>],
}

impl<'a, S: Suite> Ios<'a, S> {
    fn plain(user: &'a [VrfIo<S>]) -> Self {
        Self {
            schnorr: None,
            user,
        }
    }

    fn with_schnorr(public: AffinePoint<S>, user: &'a [VrfIo<S>]) -> Self {
        let schnorr = VrfIo {
            input: Input::from_affine_unchecked(S::generator()),
            output: Output::from_affine_unchecked(public),
        };
        Self {
            schnorr: Some(schnorr),
            user,
        }
    }

    fn len(&self) -> usize {
        self.schnorr.is_some() as usize + self.user.len()
    }

    fn iter(&self) -> impl Iterator<Item = VrfIo<S>> + '_ {
        self.schnorr.iter().chain(self.user).copied()
    }
}

/// Common VRF transcript construction: absorb scheme tag, I/O pairs, fork for
/// delinearization scalars, absorb additional data.
///
/// Returns the transcript (with ad absorbed) and the delinearization scalar
/// stream.
fn vrf_transcript_base<S: Suite>(
    scheme: DomSep,
    ios: Ios<'_, S>,
    ad: &[u8],
) -> (S::Transcript, DelinearizeScalars<S>) {
    let mut t = S::Transcript::new(S::SUITE_ID);
    t.absorb_raw(&[scheme as u8]);
    absorb_ios(&mut t, ios);
    t.absorb_raw(&(ad.len() as u64).to_le_bytes());
    t.absorb_raw(ad);
    let scalars = DelinearizeScalars::new(t.clone());
    (t, scalars)
}

/// Build a shared VRF transcript from I/O pairs and additional data.
///
/// Absorbs the scheme tag and raw I/O pairs into the transcript, derives
/// delinearization scalars from a fork (so pairs are absorbed only once),
/// merges the pairs into a single I/O, then absorbs the length-prefixed
/// additional data.
fn vrf_transcript_merged<S: Suite>(
    scheme: DomSep,
    ios: Ios<'_, S>,
    ad: &[u8],
) -> (S::Transcript, VrfIo<S>) {
    let (t, scalars) = vrf_transcript_base(scheme, ios, ad);
    let io = match ios.len() {
        0 => {
            let zero = AffinePoint::<S>::zero();
            VrfIo {
                input: Input::from_affine_unchecked(zero),
                output: Output::from_affine_unchecked(zero),
            }
        }
        1 => ios.iter().next().expect("one pair"),
        _ => merge_ios(ios, scalars),
    };
    (t, io)
}

/// Build a VRF transcript returning raw delinearization scalars.
///
/// Same transcript construction as [`vrf_transcript_merged`] but returns
/// the z scalars instead of the merged I/O pair. Used by batch verification
/// which needs the individual points and z scalars to build an expanded MSM
/// without computing the merged pair.
fn vrf_transcript_scalars<S: Suite>(
    scheme: DomSep,
    ios: Ios<'_, S>,
    ad: &[u8],
) -> (S::Transcript, Vec<ScalarField<S>>) {
    let (t, mut scalars) = vrf_transcript_base(scheme, ios, ad);
    (t, scalars.take(ios.len()))
}

pub(crate) fn vrf_transcript<S: Suite>(
    scheme: DomSep,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    vrf_transcript_merged(scheme, Ios::plain(ios.as_ref()), ad.as_ref())
}

/// Prepend the Schnorr pair `(G, Y)` to the I/O list, then build the VRF transcript.
pub(crate) fn vrf_transcript_with_schnorr<S: Suite>(
    scheme: DomSep,
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    vrf_transcript_merged(scheme, Ios::with_schnorr(public, ios.as_ref()), ad.as_ref())
}

/// Same as [`vrf_transcript_with_schnorr`] but returns the raw
/// delinearization scalars instead of the merged pair.
pub(crate) fn vrf_transcript_scalars_with_schnorr<S: Suite>(
    scheme: DomSep,
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    vrf_transcript_scalars(scheme, Ios::with_schnorr(public, ios.as_ref()), ad.as_ref())
}

/// Challenge generation inspired by RFC-9381 section 5.4.3.
///
/// Generates a challenge scalar by absorbing curve points into the transcript
/// and squeezing. Used in the Schnorr-like proofs for VRF schemes.
///
/// The transcript typically carries shared state from `vrf_transcript`.
///
/// Returns a scalar field element derived from the hash of the inputs.
pub fn challenge<S: Suite>(
    pts: &[&AffinePoint<S>],
    mut transcript: S::Transcript,
) -> ScalarField<S> {
    transcript.absorb_raw(&[DomSep::Challenge as u8]);
    for p in pts {
        transcript.absorb_serialize(*p);
    }
    challenge_scalar::<S>(&mut transcript)
}

/// Point-to-hash inspired by RFC-9381 section 5.2.
///
/// Converts an elliptic curve point to a hash value. Used to derive the
/// final VRF output bytes from the VRF output point.
///
/// The `mul_by_cofactor` flag optionally multiplies the point by the cofactor
/// before hashing, as specified in the RFC. In practice this is unnecessary
/// when `data_to_point` already yields a prime-order subgroup point.
pub fn point_to_hash<S: Suite, const N: usize>(
    pt: &AffinePoint<S>,
    mul_by_cofactor: bool,
) -> [u8; N] {
    use ark_std::borrow::Cow::*;
    let pt = match mul_by_cofactor {
        false => Borrowed(pt),
        true => Owned(pt.mul_by_cofactor()),
    };
    let mut t = S::Transcript::new(S::SUITE_ID);
    t.absorb_raw(&[DomSep::PointToHash as u8]);
    t.absorb_serialize(&*pt);
    let mut out = [0; N];
    t.squeeze_raw(&mut out);
    out
}

/// Deterministic nonce generation inspired by RFC-8032 section 5.1.6.
///
/// Hashes the secret key to derive a 64-byte expanded key, then absorbs it
/// into the transcript and squeezes a nonce. The transcript typically
/// carries shared state from `vrf_transcript`, binding the nonce to the I/O
/// pairs and additional data.
///
/// The expanded key copy and the nonce reduction buffer are zeroized. The
/// hasher states that absorbed the secret scalar and the expanded key are
/// not: see [`crate::utils::DigestXof`].
pub fn nonce<S: Suite>(sk: &ScalarField<S>, mut transcript: S::Transcript) -> ScalarField<S> {
    // Expand sk: H(transcript_state || NonceExpand || sk)
    let mut t_exp = transcript.clone();
    t_exp.absorb_raw(&[DomSep::NonceExpand as u8]);
    t_exp.absorb_serialize(sk);
    let mut sk_hash = [0u8; 64];
    t_exp.squeeze_raw(&mut sk_hash);

    // Derive nonce: H(transcript_state || Nonce || sk_hash)
    transcript.absorb_raw(&[DomSep::Nonce as u8]);
    transcript.absorb_raw(&sk_hash);
    sk_hash.zeroize();
    nonce_scalar::<S>(&mut transcript)
}

/// Stateful stream of delinearization scalars backed by a transcript's
/// squeeze stream.
///
/// The first scalar is always `1` (z_0 = 1); subsequent scalars are
/// [`Suite::SECURITY_PARAMETER`] bit values squeezed from the transcript.
pub(crate) struct DelinearizeScalars<S: Suite> {
    transcript: S::Transcript,
    first: bool,
}

impl<S: Suite> DelinearizeScalars<S> {
    /// Create a [`DelinearizeScalars`] stream from a transcript that has already
    /// absorbed the I/O pairs. Adds domain separation and starts the squeeze.
    ///
    /// The caller must have absorbed the I/O pairs into `transcript` before
    /// calling this function (e.g. via [`absorb_ios`]).
    pub fn new(mut transcript: S::Transcript) -> DelinearizeScalars<S> {
        transcript.absorb_raw(&[DomSep::Delinearize as u8]);
        DelinearizeScalars {
            transcript,
            first: true,
        }
    }

    /// Draw the next delinearization scalar.
    pub fn next(&mut self) -> ScalarField<S> {
        use ark_ff::One;
        if self.first {
            self.first = false;
            ScalarField::<S>::one()
        } else {
            weight_scalar::<S>(&mut self.transcript)
        }
    }

    /// Draw `n` delinearization scalars.
    pub fn take(&mut self, n: usize) -> Vec<ScalarField<S>> {
        (0..n).map(|_| self.next()).collect()
    }
}

/// Absorb I/O pairs into a transcript.
///
/// The count is absorbed first as a little-endian `u64` so that the
/// framing is unambiguous even though each pair is two fixed-size points.
/// This is cheap and avoids any implicit dependency on the point encoding
/// being fixed-length.
fn absorb_ios<S: Suite>(t: &mut S::Transcript, ios: Ios<'_, S>) {
    let n = ios.len() as u64;
    t.absorb_raw(&n.to_le_bytes());
    for io in ios.iter() {
        t.absorb_serialize(&io.input.0);
        t.absorb_serialize(&io.output.0);
    }
}

/// Pair count at which [`merge_ios`] switches from a fold to an MSM.
///
/// MSM has bucket-setup overhead that dominates for small N.
/// Fold is faster below this threshold; MSM wins above it.
pub(crate) const MSM_THRESHOLD: usize = 16;

/// Fold/MSM I/O pairs using pre-computed delinearization scalars.
///
/// Caller must ensure `ios.len() >= 2` and that `scalars` yields at least
/// `n` values.
fn merge_ios<S: Suite>(ios: Ios<'_, S>, mut scalars: DelinearizeScalars<S>) -> VrfIo<S> {
    let n = ios.len();

    let zero = AffinePoint::<S>::zero().into_group();
    let (input, output) = if n < MSM_THRESHOLD {
        ios.iter().fold((zero, zero), |(h_acc, g_acc), io| {
            let z = scalars.next();
            (h_acc + io.input.0 * z, g_acc + io.output.0 * z)
        })
    } else {
        let zs = scalars.take(n);
        let (inputs, outputs): (Vec<_>, Vec<_>) =
            ios.iter().map(|io| (io.input.0, io.output.0)).unzip();
        use ark_ec::VariableBaseMSM;
        type Group<S> = <AffinePoint<S> as AffineRepr>::Group;
        let input = Group::<S>::msm_unchecked(&inputs, &zs);
        let output = Group::<S>::msm_unchecked(&outputs, &zs);
        (input, output)
    };
    let norms = CurveGroup::normalize_batch(&[input, output]);
    VrfIo {
        input: Input::from_affine_unchecked(norms[0]),
        output: Output::from_affine_unchecked(norms[1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::TestSuite;

    /// Verify that the scheme tag produces distinct transcripts.
    #[test]
    fn scheme_tag_domain_separation() {
        use crate::{Input, Output, VrfIo};

        let sk = ScalarField::<TestSuite>::from(42u64);
        let ios: Vec<VrfIo<TestSuite>> = (0..3u8)
            .map(|i| {
                let input = TestSuite::data_to_point(&[i]).unwrap();
                let output = (input * sk).into_affine();
                VrfIo {
                    input: Input::from_affine_unchecked(input),
                    output: Output::from_affine_unchecked(output),
                }
            })
            .collect();

        let (_, io_tiny) = vrf_transcript::<TestSuite>(DomSep::TinyVrf, &ios, b"foo");
        let (_, io_thin) = vrf_transcript::<TestSuite>(DomSep::ThinVrf, &ios, b"foo");
        let (_, io_ped) = vrf_transcript::<TestSuite>(DomSep::PedersenVrf, &ios, b"foo");

        // Different scheme tags must produce different merged pairs (for n >= 2).
        assert_ne!(io_tiny, io_thin);
        assert_ne!(io_tiny, io_ped);
        assert_ne!(io_thin, io_ped);
    }

    /// `merge_ios` folds below `MSM_THRESHOLD` pairs and switches to an MSM
    /// at the threshold. Prover and verifier share the function, so a scalar
    /// misalignment in one branch would round-trip unnoticed. Each branch is
    /// compared with the plain sum `sum(z_i * P_i)` over scalars drawn from
    /// the same transcript fork.
    #[test]
    fn merge_ios_branches_match_plain_sum() {
        type Group = <AffinePoint<TestSuite> as AffineRepr>::Group;

        let sk = ScalarField::<TestSuite>::from(42u64);
        for n in [MSM_THRESHOLD - 1, MSM_THRESHOLD] {
            let ios: Vec<VrfIo<TestSuite>> = (0..n as u8)
                .map(|i| {
                    let input = TestSuite::data_to_point(&[i]).unwrap();
                    VrfIo {
                        input: Input::from_affine_unchecked(input),
                        output: Output::from_affine_unchecked((input * sk).into_affine()),
                    }
                })
                .collect();

            let (t, scalars) = vrf_transcript_base(DomSep::ThinVrf, Ios::plain(&ios), b"ad");
            let merged = merge_ios(Ios::plain(&ios), scalars);

            let zs = DelinearizeScalars::<TestSuite>::new(t).take(n);
            let plain_sum = |points: Vec<AffinePoint<TestSuite>>| {
                points
                    .iter()
                    .zip(&zs)
                    .map(|(point, z)| *point * z)
                    .sum::<Group>()
                    .into_affine()
            };
            let inputs = ios.iter().map(|io| io.input.0).collect();
            let outputs = ios.iter().map(|io| io.output.0).collect();
            assert_eq!(merged.input.0, plain_sum(inputs), "input, n={n}");
            assert_eq!(merged.output.0, plain_sum(outputs), "output, n={n}");
        }
    }

    /// The nonce expansion and the delinearization scalars follow
    /// `Suite::SECURITY_PARAMETER`; the challenge follows
    /// `Suite::CHALLENGE_LEN`, which defaults to the level and may exceed it.
    /// A suite at 256 bits must not get 128-bit values, and a wider challenge
    /// must not widen the delinearization scalars.
    #[test]
    fn widths_follow_security_parameter() {
        use crate::suites::testing::{TestSuite256, TestSuiteC32};

        let high_half_set = |scalar: ScalarField<TestSuite256>| {
            scalar.into_bigint().as_ref()[2..]
                .iter()
                .any(|limb| *limb != 0)
        };
        assert_eq!(TestSuite::CHALLENGE_LEN, 16);
        assert_eq!(TestSuite256::CHALLENGE_LEN, 32);
        assert_eq!(expanded_scalar_len::<TestSuite256>(), 64);
        assert_eq!(expanded_scalar_len::<TestSuite>(), 48);

        let mut t = <TestSuite256 as Suite>::Transcript::new(TestSuite256::SUITE_ID);
        assert!(high_half_set(challenge_scalar::<TestSuite256>(&mut t)));
        let t = <TestSuite256 as Suite>::Transcript::new(TestSuite256::SUITE_ID);
        let zs = DelinearizeScalars::<TestSuite256>::new(t).take(2);
        assert!(high_half_set(zs[1]));

        assert_eq!(TestSuiteC32::CHALLENGE_LEN, 32);
        assert_eq!(expanded_scalar_len::<TestSuiteC32>(), 48);
        let mut t = <TestSuiteC32 as Suite>::Transcript::new(TestSuiteC32::SUITE_ID);
        assert!(high_half_set(challenge_scalar::<TestSuiteC32>(&mut t)));
        let t = <TestSuiteC32 as Suite>::Transcript::new(TestSuiteC32::SUITE_ID);
        let zs = DelinearizeScalars::<TestSuiteC32>::new(t).take(2);
        assert!(!high_half_set(zs[1]));
    }
}
