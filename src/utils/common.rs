//! Common cryptographic utility functions.
//!
//! This module provides implementations of various cryptographic operations
//! used throughout the VRF schemes, including hashing, challenge generation,
//! and hash-to-curve algorithms.

use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::{
    hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map},
    AffineRepr,
};
use ark_ff::PrimeField;
use core::iter::Chain;
use digest::{Digest, FixedOutputReset};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

const SECURITY_BITS: usize = 128;

/// Stack buffer size for small serialized objects (compressed points, scalars).
const STACK_BUF_SIZE: usize = 128;

/// Declare a zeroed `[u8; STACK_BUF_SIZE]` array and bind `$name` to a
/// `&mut [u8]` slice of the first `$len` bytes.
///
/// Intended for small serialized objects such as single compressed points
/// or scalar field elements. Panics if `$len > STACK_BUF_SIZE`.
macro_rules! stack_buf {
    ($name:ident, $len:expr) => {
        let _sb_len: usize = $len;
        assert!(
            _sb_len <= STACK_BUF_SIZE,
            "requested {_sb_len} bytes exceeds STACK_BUF_SIZE ({STACK_BUF_SIZE})"
        );
        let mut _sb_backing = [0u8; STACK_BUF_SIZE];
        let $name = &mut _sb_backing[.._sb_len];
    };
}

/// Challenge encoding length in bytes (128-bit security).
pub const CHALLENGE_LEN: usize = SECURITY_BITS / 8;

/// This function computes the length in bytes that a hash function should output
/// for hashing an element of type `Field`.
/// See section 5.1 and 5.3 of the
/// [IETF hash-to-curve standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)
const fn get_len_per_elem<S: Suite>(sec_bits: usize) -> usize {
    // ceil(log(p))
    let base_field_size_in_bits = ScalarField::<S>::MODULUS_BIT_SIZE as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + sec_bits;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    base_field_size_with_security_padding_in_bits.div_ceil(8)
}

pub fn nonce_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    stack_buf!(buf, get_len_per_elem::<S>(SECURITY_BITS));
    t.squeeze_raw(buf);
    ScalarField::<S>::from_le_bytes_mod_order(buf)
}

pub fn challenge_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    let mut buf = [0u8; SECURITY_BITS / 8];
    t.squeeze_raw(&mut buf);
    ScalarField::<S>::from_le_bytes_mod_order(&buf)
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
    NonceExpand = 0x05,
    Nonce = 0x06,
    PedersenBlinding = 0xCC,
}

/// Common VRF transcript construction: absorb I/O pairs, fork for
/// delinearization scalars, absorb additional data.
///
/// Returns the transcript (with ad absorbed), the delinearization scalar
/// stream, and the number of I/O pairs.
fn vrf_transcript_base<S: Suite>(
    ios: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, DelinearizeScalars<S>, usize) {
    let n = ios.len();
    let mut t = S::Transcript::new(S::SUITE_ID);
    absorb_ios::<S>(&mut t, ios);
    let scalars = delinearize_scalars::<S>(n, t.clone());
    let ad_len = u32::try_from(ad.as_ref().len()).expect("ad too long");
    t.absorb_raw(&ad_len.to_le_bytes());
    t.absorb_raw(ad.as_ref());
    (t, scalars, n)
}

/// Build a shared VRF transcript from I/O pairs and additional data.
///
/// Absorbs the raw I/O pairs into the transcript, derives delinearization
/// scalars from a fork (so pairs are absorbed only once), merges the pairs
/// into a single I/O, then absorbs the length-prefixed additional data.
pub fn vrf_transcript_from_iter<S: Suite>(
    ios: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    let n = ios.len();
    let (t, scalars, _) = vrf_transcript_base(ios.clone(), ad);

    let zero = AffinePoint::<S>::zero();
    let io = if n == 0 {
        VrfIo {
            input: Input(zero),
            output: Output(zero),
        }
    } else if n == 1 {
        ios.clone().next().expect("len is 1 but iterator is empty")
    } else {
        merge_ios(ios, scalars)
    };

    (t, io)
}

/// Build a VRF transcript returning raw delinearization scalars.
///
/// Same transcript construction as [`vrf_transcript_from_iter`] but returns
/// the z scalars instead of the merged I/O pair. Used by batch verification
/// which needs the individual points and z scalars to build an expanded MSM
/// without computing the merged pair.
pub fn vrf_transcript_scalars_from_iter<S: Suite>(
    ios: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    let (t, mut scalars, n) = vrf_transcript_base(ios, ad);
    (t, scalars.take(n))
}

pub fn vrf_transcript<S: Suite>(
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    vrf_transcript_from_iter(ios.as_ref().iter().copied(), ad)
}

pub fn vrf_transcript_scalars<S: Suite>(
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    vrf_transcript_scalars_from_iter(ios.as_ref().iter().copied(), ad)
}

/// Try-And-Increment hash-to-curve, inspired by RFC-9381 section 5.4.1.1.
///
/// 1. Hashes `suite_id || 0x01 || data || ctr || 0x00` using the suite transcript.
/// 2. Attempts to interpret the hash output as a curve point via
///    [`AffineRepr::from_random_bytes`].
/// 3. Clears the cofactor and checks the point is not the identity.
/// 4. Repeats with an incremented counter (up to 256 attempts) if no valid
///    point is found.
///
/// # Returns
///
/// * `Some(AffinePoint<S>)` - A valid curve point in the prime-order subgroup.
/// * `None` - If no valid point could be found after 256 attempts.
pub fn hash_to_curve_tai<S: Suite>(data: &[u8]) -> Option<AffinePoint<S>> {
    let base_len = BaseField::<S>::default().serialized_size(ark_serialize::Compress::Yes);
    stack_buf!(hash, base_len);

    let mut prefix = S::Transcript::new(S::SUITE_ID);
    prefix.absorb_raw(&[DomSep::HashToCurveTai as u8]);
    prefix.absorb_raw(data);

    for ctr in 0..=255_u8 {
        let mut t = prefix.clone();
        t.absorb_raw(&[ctr]);
        t.squeeze_raw(hash);
        let Some(pt) = AffinePoint::<S>::from_random_bytes(hash) else {
            continue;
        };
        let pt = pt.clear_cofactor();
        if !pt.is_zero() {
            return Some(pt);
        }
    }
    None
}

/// Elligator2 hash-to-curve, inspired by RFC-9380 and RFC-9381 section 5.4.1.2.
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
pub fn hash_to_curve_ell2<S: Suite, H>(data: &[u8], h2c_suite_id: &[u8]) -> Option<AffinePoint<S>>
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

/// Challenge generation inspired by RFC-9381 section 5.4.3.
///
/// Generates a challenge scalar by absorbing curve points into the transcript
/// and squeezing. Used in the Schnorr-like proofs for VRF schemes.
///
/// When `transcript` is `Some`, uses the pre-built transcript (which typically
/// carries shared state from `vrf_transcript`). When `None`, creates a fresh
/// transcript from `SUITE_ID`.
///
/// Returns a scalar field element derived from the hash of the inputs.
pub fn challenge<S: Suite>(
    pts: &[&AffinePoint<S>],
    transcript: Option<S::Transcript>,
) -> ScalarField<S> {
    let mut t = transcript.unwrap_or_else(|| S::Transcript::new(S::SUITE_ID));
    t.absorb_raw(&[DomSep::Challenge as u8]);
    for p in pts {
        t.absorb_serialize(*p);
    }
    challenge_scalar::<S>(&mut t)
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
/// Hashes the secret key to derive a 64-byte expanded key, then absorbs the
/// upper half into the transcript and squeezes a nonce. The transcript typically
/// carries shared state from `vrf_transcript`, binding the nonce to the I/O
/// pairs and additional data.
pub fn nonce<S: Suite>(sk: &ScalarField<S>, transcript: Option<S::Transcript>) -> ScalarField<S> {
    let mut t = transcript.unwrap_or_else(|| S::Transcript::new(S::SUITE_ID));

    // Expand sk: H(transcript_state || NonceExpand || sk)
    let mut t_exp = t.clone();
    t_exp.absorb_raw(&[DomSep::NonceExpand as u8]);
    t_exp.absorb_serialize(sk);
    let mut sk_hash = [0u8; 64];
    t_exp.squeeze_raw(&mut sk_hash);

    // Derive nonce: H(transcript_state || Nonce || sk_hash[32..])
    t.absorb_raw(&[DomSep::Nonce as u8]);
    t.absorb_raw(&sk_hash[32..]);
    nonce_scalar::<S>(&mut t)
}

/// Stateful stream of 128-bit delinearization scalars backed by a transcript's
/// squeeze stream. Created by [`delinearize_scalars`].
pub(crate) struct DelinearizeScalars<S: Suite> {
    transcript: S::Transcript,
}

impl<S: Suite> DelinearizeScalars<S> {
    /// Draw the next 128-bit scalar.
    pub fn next(&mut self) -> ScalarField<S> {
        challenge_scalar::<S>(&mut self.transcript)
    }

    /// Collect `n` scalars into a `Vec`.
    pub fn take(&mut self, n: usize) -> Vec<ScalarField<S>> {
        (0..n).map(|_| self.next()).collect()
    }
}

/// Create a [`DelinearizeScalars`] stream from a transcript that has already
/// absorbed the I/O pairs. Adds domain separation and starts the squeeze.
///
/// The caller must have absorbed the I/O pairs into `transcript` before
/// calling this function (e.g. via [`absorb_ios`]).
pub(crate) fn delinearize_scalars<S: Suite>(
    n: usize,
    mut transcript: S::Transcript,
) -> DelinearizeScalars<S> {
    let n = u32::try_from(n).expect("too many input-output pairs");
    transcript.absorb_raw(&[DomSep::Delinearize as u8]);
    transcript.absorb_raw(&n.to_le_bytes());
    DelinearizeScalars { transcript }
}

/// Absorb I/O pairs into a transcript.
pub(crate) fn absorb_ios<S: Suite>(t: &mut S::Transcript, ios: impl Iterator<Item = VrfIo<S>>) {
    for io in ios {
        t.absorb_serialize(&io);
    }
}

/// Fold/MSM I/O pairs using pre-computed delinearization scalars.
///
/// Caller must ensure `iter.len() >= 2` and that `scalars` yields at least
/// that many values.
fn merge_ios<S: Suite>(
    iter: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    mut scalars: DelinearizeScalars<S>,
) -> VrfIo<S> {
    let n = iter.len();

    // MSM has bucket-setup overhead that dominates for small N.
    // Fold is faster below this threshold; MSM wins above it.
    const MSM_THRESHOLD: usize = 16;

    let zero = AffinePoint::<S>::zero().into_group();
    let (input, output) = if n < MSM_THRESHOLD {
        iter.fold((zero, zero), |(h_acc, g_acc), io| {
            let z = scalars.next();
            (h_acc + io.input.0 * z, g_acc + io.output.0 * z)
        })
    } else {
        let scalars = scalars.take(n);
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
        return iter.clone().next().expect("len is 1 but iterator is empty");
    }

    let mut t = transcript.unwrap_or_else(|| S::Transcript::new(S::SUITE_ID));
    absorb_ios(&mut t, iter.clone());
    merge_ios(iter, delinearize_scalars::<S>(n, t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::TestSuite;

    #[test]
    fn hash_to_curve_tai_works() {
        let pt = hash_to_curve_tai::<TestSuite>(b"hello world").unwrap();
        // Check that `pt` is in the prime subgroup
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }

    #[test]
    fn vrf_transcript_merged_pair_matches_delinearize() {
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

        // vrf_transcript_from_iter's merged pair must match standalone delinearize.
        let (_, io_from_transcript) = vrf_transcript::<TestSuite>(&ios, b"foo");
        let io_standalone = delinearize::<TestSuite>(ios.iter().copied(), None);
        assert_eq!(
            io_from_transcript, io_standalone,
            "merged I/O pair mismatch"
        );
    }
}
