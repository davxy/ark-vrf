//! Common cryptographic utility functions.
//!
//! This module provides implementations of various cryptographic operations
//! used throughout the VRF schemes, including hashing, challenge generation,
//! and hash-to-curve algorithms.

use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::{
    hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map},
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    AffineRepr,
};
use core::iter::Chain;
use digest::{Digest, FixedOutputReset};
use generic_array::typenum::Unsigned;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Construct an affine point from a single base field coordinate.
///
/// For SW curves the coordinate is x; for TE curves it is y.
/// Returns the point with the "positive" (smaller) second coordinate,
/// or `None` if no point exists for the given input.
pub trait PointFromCoord: AffineRepr {
    fn from_coord(coord: Self::BaseField) -> Option<Self>;
}

impl<P: SWCurveConfig> PointFromCoord for SWAffine<P> {
    fn from_coord(x: Self::BaseField) -> Option<Self> {
        Self::get_point_from_x_unchecked(x, false)
    }
}

impl<P: TECurveConfig> PointFromCoord for TEAffine<P> {
    fn from_coord(y: Self::BaseField) -> Option<Self> {
        Self::get_point_from_y_unchecked(y, false)
    }
}

/// Wrapper around [`Chain`] that implements [`ExactSizeIterator`].
///
/// Safe because the constituent iterators are both `ExactSizeIterator`
/// with small lengths (VRF I/O pairs), so overflow is not a concern.
#[derive(Clone)]
pub struct ExactChain<A, B>(Chain<A, B>, usize);

impl<A, B> ExactChain<A, B>
where
    A: ExactSizeIterator,
    B: ExactSizeIterator<Item = A::Item>,
{
    pub fn new(a: A, b: B) -> Self {
        let len = a.len() + b.len();
        Self(a.chain(b), len)
    }
}

impl<A, B> Iterator for ExactChain<A, B>
where
    A: Iterator,
    B: Iterator<Item = A::Item>,
{
    type Item = A::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next();
        if item.is_some() {
            self.1 -= 1;
        }
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.1, Some(self.1))
    }
}

impl<A, B> ExactSizeIterator for ExactChain<A, B>
where
    A: Iterator,
    B: Iterator<Item = A::Item>,
{
}

/// Internal domain separation tags for protocol hashing.
#[repr(u8)]
pub(crate) enum DomSep {
    HashToCurveTai = 0x01,
    Challenge = 0x02,
    PointToHash = 0x03,
    Delinearize = 0x04,
    PedersenBlinding = 0xCC,
    End = 0x00,
}

/// Build a shared VRF transcript from I/O pairs and additional data.
///
/// Creates a transcript from `SUITE_ID`, delinearizes the I/O pairs into a
/// single merged pair (so that delinearization is stable for a given I/O set,
/// independent of `ad`), absorbs the merged pair, then absorbs the
/// length-prefixed additional data so that all subsequent forks (nonce,
/// blinding, challenge) inherit the same state.
pub fn vrf_transcript<S: Suite>(
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    let mut t = S::Transcript::new(S::SUITE_ID);
    let io = delinearize(ios.as_ref().iter().copied(), Some(t.clone()));
    t.absorb_serialize(&io);
    let ad_len = u32::try_from(ad.as_ref().len()).expect("ad too long");
    t.absorb_raw(&ad_len.to_le_bytes());
    t.absorb_raw(ad.as_ref());
    (t, io)
}

/// Try-And-Increment method inspired by RFC-9381 section 5.4.1.1.
///
/// This implementation deviates from RFC-9381 in how the hash output is
/// interpreted as a field element. The RFC defines a suite-specific
/// `interpret_hash_value_as_a_point` function (e.g. `string_to_point(0x02 || s)`
/// for P-256) that treats the hash as a serialized compressed point, coupling
/// the procedure to the curve type and serialization format.
///
/// Instead, this implementation:
/// 1. Hashes `suite_id || 0x01 || data || ctr || 0x00` using `Suite::Hasher`.
/// 2. Reduces the hash output modulo the base field prime (little-endian) to
///    obtain a field element. This uses all hash bytes and always produces a
///    valid field element, introducing a negligible bias of ~`p / 2^hash_bits`
///    when the hash is larger than the field (e.g. SHA-512 on a 255-bit field).
/// 3. Interprets the field element as a curve coordinate via [`PointFromCoord`]:
///    x-coordinate for short Weierstrass, y-coordinate for twisted Edwards.
///    The "positive" (smaller) second coordinate is always selected.
/// 4. Clears the cofactor and checks the point is not the identity.
/// 5. Repeats with an incremented counter (up to 256 attempts) if no valid
///    point is found.
///
/// # Returns
///
/// * `Some(AffinePoint<S>)` - A valid curve point in the prime-order subgroup.
/// * `None` - If no valid point could be found after 256 attempts.
pub fn hash_to_curve_tai_rfc_9381<S: Suite>(data: &[u8]) -> Option<AffinePoint<S>>
where
    AffinePoint<S>: PointFromCoord,
    BaseField<S>: ark_ff::PrimeField,
{
    let mut prefix = S::Transcript::new(S::SUITE_ID);
    prefix.absorb_raw(&[DomSep::HashToCurveTai as u8]);
    prefix.absorb_raw(data);

    let hash_len = <S::Transcript as Transcript>::OutputSize::to_usize();
    for ctr in 0..=255u8 {
        let mut t = prefix.clone();
        t.absorb_raw(&[ctr, DomSep::End as u8]);
        // TODO: remove this hash_len and use the sample technique with security level bits
        let mut hash = ark_std::vec![0u8; hash_len];
        t.squeeze_raw(&mut hash);
        let coord = BaseField::<S>::from_le_bytes_mod_order(&hash);
        let Some(pt) = AffinePoint::<S>::from_coord(coord) else {
            continue;
        };
        let pt = pt.clear_cofactor();
        if !pt.is_zero() {
            return Some(pt);
        }
    }
    None
}

/// Elligator2 method as defined by RFC-9380 and further refined in RFC-9381 section 5.4.1.2.
///
/// Implements ECVRF_encode_to_curve using one of the several hash-to-curve options defined
/// in RFC-9380. This method provides a constant-time hash-to-curve implementation that is
/// more secure against side-channel attacks than the Try-And-Increment method.
///
/// The specific choice of the hash-to-curve option (called the Suite ID in RFC-9380)
/// is given by the h2c_suite_ID_string parameter.
///
/// This function requires an additional `Hasher` type parameter because the arkworks
/// hash-to-curve API (`DefaultFieldHasher`) needs a raw `Digest` type. This is separate
/// from the suite's transcript.
///
/// # Parameters
///
/// * `data` - The input data to hash to a curve point
///   (defined to be `salt || alpha` according to RFC-9381)
/// * `h2c_suite_id` - The hash-to-curve suite identifier as defined in RFC-9380
///
/// # Returns
///
/// * `Some(AffinePoint<S>)` - A valid curve point in the prime-order subgroup
/// * `None` - If the hash-to-curve operation fails
#[allow(unused)]
pub fn hash_to_curve_ell2_rfc_9380<S: Suite, H>(
    data: &[u8],
    h2c_suite_id: &[u8],
) -> Option<AffinePoint<S>>
where
    H: Digest + Default + Clone + FixedOutputReset + 'static,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ec::hashing::{map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
    use ark_ff::field_hashers::DefaultFieldHasher;

    // Domain Separation Tag := "ECVRF_" || h2c_suite_ID_string || suite_string
    let dst: Vec<_> = [b"ECVRF_", h2c_suite_id, S::SUITE_ID].concat();

    MapToCurveBasedHasher::<
        <AffinePoint<S> as AffineRepr>::Group,
        DefaultFieldHasher<H, 128>,
        Elligator2Map<CurveConfig<S>>,
    >::new(&dst)
    .and_then(|hasher| hasher.hash(data))
    .ok()
}

/// Challenge generation according to RFC-9381 section 5.4.3.
///
/// Generates a challenge scalar by hashing a sequence of curve points and additional data.
/// This is used in the Schnorr-like signature scheme for VRF proofs.
///
/// When `transcript` is `Some`, uses the pre-built transcript which may already
/// carry shared state. When `None`, creates a fresh transcript from `SUITE_ID`.
///
/// # Parameters
///
/// * `transcript` - Optional pre-built transcript with accumulated state
/// * `pts` - Array of curve points to include in the challenge
/// * `ad` - Additional data to bind to the challenge
///
/// Returns a scalar field element derived from the hash of the inputs
pub fn challenge_rfc_9381<S: Suite>(
    pts: &[&AffinePoint<S>],
    ad: &[u8],
    transcript: Option<S::Transcript>,
) -> ScalarField<S> {
    let mut t = transcript.unwrap_or_else(|| S::Transcript::new(S::SUITE_ID));
    t.absorb_raw(&[DomSep::Challenge as u8]);
    for p in pts {
        t.absorb_serialize(*p);
    }
    t.absorb_raw(ad);
    t.absorb_raw(&[DomSep::End as u8]);
    // TODO: sample using security level bits
    let mut hash = ark_std::vec![0u8; S::CHALLENGE_LEN];
    t.squeeze_raw(&mut hash);
    S::Codec::scalar_decode(&hash)
}

/// Point to a hash according to RFC-9381 section 5.2.
///
/// Converts an elliptic curve point to a hash value, following the procedure in RFC-9381.
/// This is used to derive the final VRF output bytes from the VRF output point.
///
/// According to the RFC, the input point `pt` should be multiplied by the cofactor
/// before being hashed. However, in typical usage, the hashed point is the result
/// of a scalar multiplication on a point produced by the `Suite::data_to_point`
/// (also referred to as the _hash-to-curve_ or _h2c_) algorithm, which is expected
/// to yield a point that already belongs to the prime order subgroup of the curve.
///
/// Therefore, assuming the `data_to_point` function is implemented correctly, the
/// input point `pt` will inherently reside in the prime order subgroup, making the
/// cofactor multiplication unnecessary and redundant in terms of security. The primary
/// purpose of multiplying by the cofactor is as a safeguard against potential issues
/// with an incorrect implementation of `data_to_point`.
///
/// # Parameters
///
/// * `pt` - The elliptic curve point to hash
/// * `mul_by_cofactor` - Whether to multiply the point by the cofactor before hashing
///
/// # Returns
///
/// A hash value derived from the encoded point
pub fn point_to_hash_rfc_9381<S: Suite, const N: usize>(
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
    t.absorb_raw(&[DomSep::End as u8]);
    let mut out = [0; N];
    t.squeeze_raw(&mut out);
    out
}

/// Nonce generation according to RFC-9381 section 5.4.2.2.
///
/// This procedure is based on section 5.1.6 of RFC 8032: "Edwards-Curve Digital
/// Signature Algorithm (EdDSA)". It generates a deterministic nonce by hashing
/// the secret key and input point together.
///
/// The deterministic generation ensures that the same nonce is never used twice
/// with the same secret key for different inputs, which is critical for security.
///
/// The `ad` (additional data) is mixed into the hash to ensure distinct nonces
/// when the same secret key and input are used with different auxiliary data.
///
/// # Parameters
///
/// * `sk` - The secret scalar key
/// * `pts` - Points to bind into the nonce derivation
/// * `ad` - Additional data bound to the proof
///
/// # Returns
///
/// A scalar field element to be used as a nonce
///
/// # Panics
///
/// This function panics if the transcript output is less than 64 bytes.
pub fn nonce_rfc_8032<S: Suite>(
    sk: &ScalarField<S>,
    pts: &[&AffinePoint<S>],
    ad: &[u8],
    transcript: Option<S::Transcript>,
) -> ScalarField<S> {
    // First hash: H(sk)
    let mut t1 = S::Transcript::new(b"");
    t1.absorb_serialize(sk);
    let mut sk_hash = [0u8; 64];
    t1.squeeze_raw(&mut sk_hash);

    // Second hash: H(sk_hash[32..] || pts || ad)
    let mut t2 = transcript.unwrap_or_else(|| S::Transcript::new(b""));
    t2.absorb_raw(&sk_hash[32..]);
    for pt in pts {
        t2.absorb_serialize(*pt);
    }
    t2.absorb_raw(ad);
    let mut h = [0u8; 64];
    t2.squeeze_raw(&mut h);
    S::Codec::scalar_decode(&h)
}

/// Nonce generation using transcript-based deterministic derivation.
///
/// Replacement for RFC-6979 HMAC-DRBG. Uses the suite's transcript to derive
/// a deterministic nonce from the secret key, points, and additional data.
///
/// # Parameters
///
/// * `sk` - The secret scalar key
/// * `pts` - Points to bind into the nonce derivation
/// * `ad` - Additional data bound to the proof
///
/// # Returns
///
/// A scalar field element to be used as a nonce
pub fn nonce_transcript<S: Suite>(
    sk: &ScalarField<S>,
    pts: &[&AffinePoint<S>],
    ad: &[u8],
    transcript: Option<S::Transcript>,
) -> ScalarField<S> {
    let mut t = transcript.unwrap_or_else(|| S::Transcript::new(S::SUITE_ID));
    t.absorb_raw(b"nonce");
    t.absorb_serialize(sk);
    for pt in pts {
        t.absorb_serialize(*pt);
    }
    t.absorb_raw(ad);

    let scalar_len = S::Codec::SCALAR_ENCODED_LEN;
    let mut buf = ark_std::vec![0u8; scalar_len];
    loop {
        t.squeeze_raw(&mut buf);
        let nonce = S::Codec::scalar_decode(&buf);
        if !nonce.is_zero() {
            return nonce;
        }
    }
}

/// Stateful stream of 128-bit delinearization scalars backed by a transcript's
/// squeeze stream. Created by [`delinearize_scalars`].
pub(crate) struct DelinearizeScalars<S: Suite> {
    transcript: S::Transcript,
}

impl<S: Suite> DelinearizeScalars<S> {
    /// Draw the next 128-bit scalar.
    pub fn next(&mut self) -> ScalarField<S> {
        super::transcript::squeeze_scalar::<S>(&mut self.transcript)
    }

    /// Collect `n` scalars into a `Vec`.
    pub fn take_vec(&mut self, n: usize) -> Vec<ScalarField<S>> {
        (0..n).map(|_| self.next()).collect()
    }
}

/// Create a [`DelinearizeScalars`] stream from an iterator of [`VrfIo`] pairs.
/// The scalars are derived deterministically by hashing all encoded points
/// and squeezing from the transcript.
pub(crate) fn delinearize_scalars<S: Suite>(
    iter: impl ExactSizeIterator<Item = VrfIo<S>>,
    transcript: Option<S::Transcript>,
) -> DelinearizeScalars<S> {
    let n = u32::try_from(iter.len()).expect("too many input-output pairs");

    let mut t = transcript.unwrap_or_else(|| S::Transcript::new(S::SUITE_ID));
    t.absorb_raw(&[DomSep::Delinearize as u8]);
    t.absorb_raw(&n.to_le_bytes());
    for io in iter {
        t.absorb_serialize(&io);
    }
    t.absorb_raw(&[DomSep::End as u8]);
    DelinearizeScalars { transcript: t }
}

/// Delinearize multiple input-output pairs into a single pair.
///
/// Derives 128-bit delinearization scalars (Privacy Pass / dleq_vrf technique)
/// and folds the ios into `(sum(z_i * input_i), sum(z_i * output_i))`.
/// The resulting `(Input, Output)` can be passed directly to a scheme's
/// `prove` / `verify` to obtain or check a single proof covering all pairs.
///
/// The ordering of items matters: the delinearization scalars are derived from
/// the hash of the pairs in the given order, so the prover and verifier must
/// use the same ordering to obtain the same merged pair.
///
/// - N=0: returns the identity point for both input and output.
/// - N=1: returns the pair as-is, no hashing or scalar multiplications.
/// - N>1: derives per-pair 128-bit scalars (2^{-128} Schwartz-Zippel soundness)
///   and returns their linear combination.
///
/// The iterator must be `ExactSizeIterator` (to know N) and `Clone` (for the
/// two-pass hash-then-fold without allocation).
///
/// # WARNING: N=0
///
/// When the iterator is empty, both returned points are the identity (zero point).
/// Since `sk * 0 = 0` for every secret key, the resulting DLEQ proof degenerates
/// into a Schnorr signature over the additional data -- it binds the public key
/// but provides **no VRF output**. The `Output` is a public constant
/// (the identity point) and **must not** be used to derive VRF randomness.
/// Doing so would produce a predictable, key-independent value.
pub fn delinearize<S: Suite>(
    iter: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    transcript: Option<S::Transcript>,
) -> VrfIo<S> {
    let zero = AffinePoint::<S>::zero();
    let n = iter.len();

    if n == 0 {
        return VrfIo {
            input: Input(zero),
            output: Output(zero),
        };
    }

    if n == 1 {
        let io = iter.clone().next().expect("len is 1 but iterator is empty");
        return io;
    }

    // MSM has bucket-setup overhead that dominates for small N.
    // Fold is faster below this threshold; MSM wins above it.
    const MSM_THRESHOLD: usize = 16;

    let mut scalars = delinearize_scalars(iter.clone(), transcript);

    let zero = zero.into_group();
    let (input, output) = if n < MSM_THRESHOLD {
        iter.fold((zero, zero), |(h_acc, g_acc), io| {
            let z = scalars.next();
            (h_acc + io.input.0 * z, g_acc + io.output.0 * z)
        })
    } else {
        let scalars = scalars.take_vec(n);
        let (inputs, outputs): (Vec<_>, Vec<_>) = iter.map(|io| (io.input.0, io.output.0)).unzip();
        use ark_ec::VariableBaseMSM;
        type Group<S> = <AffinePoint<S> as AffineRepr>::Group;
        let input = Group::<S>::msm_unchecked(&inputs, &scalars);
        let output = Group::<S>::msm_unchecked(&outputs, &scalars);
        (input, output)
    };
    let norms = CurveGroup::normalize_batch(&[input, output]);
    VrfIo {
        input: Input(norms[0]),
        output: Output(norms[1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::TestSuite;

    #[test]
    fn hash_to_curve_tai_works() {
        let pt = hash_to_curve_tai_rfc_9381::<TestSuite>(b"hello world").unwrap();
        // Check that `pt` is in the prime subgroup
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }

    #[test]
    fn vrf_transcript_delinearize_equivalence() {
        use crate::{Input, Output, VrfIo};

        let sk = ScalarField::<TestSuite>::from(42u64);
        let ios: Vec<VrfIo<TestSuite>> = (0..3u8)
            .map(|i| {
                let input = TestSuite::data_to_point(&[i]).unwrap();
                let output = (input * sk).into_affine();
                VrfIo {
                    input: Input(input),
                    output: Output(output),
                }
            })
            .collect();

        let ad = b"foo";

        // Path 1: delinearize first, then vrf_transcript with the single merged io
        let merged = delinearize::<TestSuite>(ios.iter().copied(), None);
        let (mut t1, io1) = vrf_transcript::<TestSuite>(merged, ad);

        // Path 2: vrf_transcript directly with all 3 ios
        let (mut t2, io2) = vrf_transcript::<TestSuite>(&ios, ad);

        assert_eq!(io1, io2, "merged I/O pair mismatch");

        // Verify transcript states match by squeezing the same amount
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        t1.squeeze_raw(&mut out1);
        t2.squeeze_raw(&mut out2);
        assert_eq!(out1, out2, "transcript state mismatch");
    }
}
