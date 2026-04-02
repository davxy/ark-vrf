//! Common cryptographic utility functions.
//!
//! This module provides implementations of various cryptographic operations
//! used throughout the VRF schemes, including challenge generation, nonce
//! derivation, and delinearization.

use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use core::iter::Chain;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Target security level in bits.
///
/// Used to size scalar expansions (see [`expanded_scalar_len`]) and hash-to-field
/// outputs so that modular reduction bias is at most `2^{-k}` where `k` is this
/// value. Also determines the challenge encoding length ([`CHALLENGE_LEN`]).
///
/// Set to 128, matching the security level of the curves we target (Bandersnatch,
/// Ed25519, JubJub).
pub(crate) const SECURITY_PARAMETER: usize = 128;

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
pub const CHALLENGE_LEN: usize = SECURITY_PARAMETER / 8;

/// Number of bytes to squeeze for an unbiased scalar via `from_le_bytes_mod_order`.
///
/// Returns `ceil((ceil(log2(p)) + sec_bits) / 8)` where `p` is the scalar field
/// modulus. The extra `sec_bits` padding ensures that the bias from modular
/// reduction is at most `2^{-sec_bits}`.
///
/// See sections 5.1 and 5.3 of the
/// [IETF hash-to-curve draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/).
pub const fn expanded_scalar_len<S: Suite>(sec_bits: usize) -> usize {
    // ceil(log(p))
    let base_field_size_in_bits = ScalarField::<S>::MODULUS_BIT_SIZE as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + sec_bits;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    base_field_size_with_security_padding_in_bits.div_ceil(8)
}

pub fn nonce_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    stack_buf!(buf, expanded_scalar_len::<S>(SECURITY_PARAMETER));
    t.squeeze_raw(buf);
    ScalarField::<S>::from_le_bytes_mod_order(buf)
}

pub fn challenge_scalar<S: Suite>(t: &mut S::Transcript) -> ScalarField<S> {
    let mut buf = [0u8; SECURITY_PARAMETER / 8];
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
    TinyVrf = 0x00,
    ThinVrf = 0x01,
    PedersenVrf = 0x02,
    NonceExpand = 0x10,
    Nonce = 0x11,
    PedersenBlinding = 0x12,
    PointToHash = 0x20,
    Delinearize = 0x30,
    Challenge = 0x40,
    ThinBatch = 0x50,
    PedersenBatch = 0x51,
    HashToCurveTai = 0xFE,
}

/// Common VRF transcript construction: absorb scheme tag, I/O pairs, fork for
/// delinearization scalars, absorb additional data.
///
/// Returns the transcript (with ad absorbed), the delinearization scalar
/// stream, and the number of I/O pairs.
fn vrf_transcript_base<S: Suite>(
    scheme: DomSep,
    ios: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, DelinearizeScalars<S>, usize) {
    let n = ios.len();
    let mut t = S::Transcript::new(S::SUITE_ID);
    t.absorb_raw(&[scheme as u8]);
    absorb_ios::<S>(&mut t, ios);
    let ad_len = u32::try_from(ad.as_ref().len()).expect("ad too long");
    t.absorb_raw(&ad_len.to_le_bytes());
    t.absorb_raw(ad.as_ref());
    let scalars = DelinearizeScalars::new(t.clone());
    (t, scalars, n)
}

/// Build a shared VRF transcript from I/O pairs and additional data.
///
/// Absorbs the scheme tag and raw I/O pairs into the transcript, derives
/// delinearization scalars from a fork (so pairs are absorbed only once),
/// merges the pairs into a single I/O, then absorbs the length-prefixed
/// additional data.
pub(crate) fn vrf_transcript_from_iter<S: Suite>(
    scheme: DomSep,
    ios: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    let n = ios.len();
    let (t, scalars, _) = vrf_transcript_base(scheme, ios.clone(), ad);

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
pub(crate) fn vrf_transcript_scalars_from_iter<S: Suite>(
    scheme: DomSep,
    ios: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    let (t, mut scalars, n) = vrf_transcript_base(scheme, ios, ad);
    (t, scalars.take(n))
}

pub(crate) fn vrf_transcript<S: Suite>(
    scheme: DomSep,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    vrf_transcript_from_iter(scheme, ios.as_ref().iter().copied(), ad)
}

/// Prepend the Schnorr pair `(G, Y)` to the I/O list, then build the VRF transcript.
///
/// Used by Tiny and Thin VRF where the public key DLEQ relation is folded
/// into the delinearized I/O pairs.
fn chain_ios<'a, S: Suite>(
    public: AffinePoint<S>,
    ios: &'a [VrfIo<S>],
) -> impl ExactSizeIterator<Item = VrfIo<S>> + Clone + 'a {
    let schnorr = core::iter::once(VrfIo {
        input: Input(S::generator()),
        output: Output(public),
    });
    ExactChain::new(schnorr, ios.iter().copied())
}

pub(crate) fn vrf_transcript_with_schnorr<S: Suite>(
    scheme: DomSep,
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    vrf_transcript_from_iter(scheme, chain_ios(public, ios.as_ref()), ad)
}

pub(crate) fn vrf_transcript_scalars_with_schnorr<S: Suite>(
    scheme: DomSep,
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    vrf_transcript_scalars_from_iter(scheme, chain_ios(public, ios.as_ref()), ad)
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

    // Derive nonce: H(transcript_state || Nonce || sk_hash)
    t.absorb_raw(&[DomSep::Nonce as u8]);
    t.absorb_raw(&sk_hash);
    sk_hash.zeroize();
    nonce_scalar::<S>(&mut t)
}

/// Stateful stream of delinearization scalars backed by a transcript's
/// squeeze stream.
///
/// The first scalar is always `1` (z_0 = 1); subsequent scalars are
/// 128-bit values squeezed from the transcript.
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
            challenge_scalar::<S>(&mut self.transcript)
        }
    }

    /// Draw `n` delinearization scalars.
    pub fn take(&mut self, n: usize) -> Vec<ScalarField<S>> {
        (0..n).map(|_| self.next()).collect()
    }
}

/// Absorb I/O pairs into a transcript.
///
/// The count is absorbed first as a little-endian `u32` so that the
/// framing is unambiguous even though each `VrfIo` already has a
/// fixed-size serialization. This is cheap and avoids any implicit
/// dependency on the serialization being fixed-length.
fn absorb_ios<S: Suite>(t: &mut S::Transcript, ios: impl ExactSizeIterator<Item = VrfIo<S>>) {
    let n = u32::try_from(ios.len()).expect("too many ios");
    t.absorb_raw(&n.to_le_bytes());
    for io in ios {
        t.absorb_serialize(&io);
    }
}

/// Fold/MSM I/O pairs using pre-computed delinearization scalars.
///
/// Caller must ensure `iter.len() >= 2` and that `scalars` yields at least
/// `n` values.
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
        let zs = scalars.take(n);
        let (inputs, outputs): (Vec<_>, Vec<_>) = iter.map(|io| (io.input.0, io.output.0)).unzip();
        use ark_ec::VariableBaseMSM;
        type Group<S> = <AffinePoint<S> as AffineRepr>::Group;
        let input = Group::<S>::msm_unchecked(&inputs, &zs);
        let output = Group::<S>::msm_unchecked(&outputs, &zs);
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
                    input: Input(input),
                    output: Output(output),
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
}
