//! Challenge, nonce, transcript and delinearization helpers of the schemes.

use crate::utils::straus::short_msm;
use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Stack buffer size for small serialized objects (compressed points, scalars).
pub(crate) const STACK_BUF_SIZE: usize = 128;

/// Bind `$name` to a zeroed stack slice of `$len` bytes. Panics if
/// `$len > STACK_BUF_SIZE`.
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

/// Bytes to squeeze for a scalar whose reduction bias is at most
/// `2^-SECURITY_PARAMETER`: `ceil((ceil(log2(p)) + SECURITY_PARAMETER) / 8)`.
///
/// See sections 5.1 and 5.3 of the
/// [hash-to-curve draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/).
pub const fn expanded_scalar_len<S: Suite>() -> usize {
    let base_field_size_in_bits = ScalarField::<S>::MODULUS_BIT_SIZE as usize;
    (base_field_size_in_bits + S::SECURITY_PARAMETER).div_ceil(8)
}

/// Squeeze [`expanded_scalar_len`] bytes and reduce them into a scalar.
/// The bytes are zeroized after the reduction.
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

/// Domain separation tags, absorbed as one byte after `SUITE_ID`. The values
/// are in blocks of sixteen by purpose.
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

/// I/O pairs of a VRF transcript: the Schnorr pair `(G, Y)` of Tiny and Thin
/// VRF, if any, and then the user pairs.
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
            input: Input::from_affine_unchecked(S::GENERATOR),
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

/// Common VRF transcript construction: absorb the scheme tag, the I/O pairs
/// and the length-prefixed additional data.
fn vrf_transcript<S: Suite>(scheme: DomSep, ios: Ios<'_, S>, ad: &[u8]) -> S::Transcript {
    let mut t = S::Transcript::new(S::SUITE_ID);
    t.absorb_raw(&[scheme as u8]);
    absorb_ios(&mut t, ios);
    t.absorb_raw(&(ad.len() as u64).to_le_bytes());
    t.absorb_raw(ad);
    t
}

/// [`vrf_transcript`], then fork for the delinearization scalars.
///
/// Returns the transcript (with ad absorbed) and the delinearization scalar
/// stream.
fn vrf_transcript_base<S: Suite>(
    scheme: DomSep,
    ios: Ios<'_, S>,
    ad: &[u8],
) -> (S::Transcript, DelinearizeScalars<S>) {
    let t = vrf_transcript(scheme, ios, ad);
    let scalars = DelinearizeScalars::new(t.clone());
    (t, scalars)
}

/// Merge the I/O pairs into a single pair with scalars from `scalars`.
fn merged_pair<S: Suite>(ios: Ios<'_, S>, mut scalars: DelinearizeScalars<S>) -> VrfIo<S> {
    match ios.len() {
        0 => {
            let zero = AffinePoint::<S>::zero();
            VrfIo {
                input: Input::from_affine_unchecked(zero),
                output: Output::from_affine_unchecked(zero),
            }
        }
        1 => ios.iter().next().expect("one pair"),
        n => merge_ios(ios, &scalars.take(n)),
    }
}

/// Same as [`merged_pair`], but merges the inputs only.
///
/// The provers commit their nonce to the merged input alone, so the merged
/// output is never built.
fn merged_input<S: Suite>(ios: Ios<'_, S>, mut scalars: DelinearizeScalars<S>) -> Input<S> {
    match ios.len() {
        0 => Input::from_affine_unchecked(AffinePoint::<S>::zero()),
        1 => ios.iter().next().expect("one pair").input,
        n => merge_inputs(ios, &scalars.take(n)),
    }
}

/// Build the VRF transcript and the merged input.
fn vrf_transcript_merged_input<S: Suite>(
    scheme: DomSep,
    ios: Ios<'_, S>,
    ad: &[u8],
) -> (S::Transcript, Input<S>) {
    let (t, scalars) = vrf_transcript_base(scheme, ios, ad);
    (t, merged_input(ios, scalars))
}

/// Same as [`vrf_transcript_merged_input`], but returns the delinearization
/// scalars. The batch verifiers use them on the raw points.
fn vrf_transcript_scalars<S: Suite>(
    scheme: DomSep,
    ios: Ios<'_, S>,
    ad: &[u8],
) -> (S::Transcript, Vec<ScalarField<S>>) {
    let (t, mut scalars) = vrf_transcript_base(scheme, ios, ad);
    (t, scalars.take(ios.len()))
}

/// [`vrf_transcript`] over plain I/O pairs, without the delinearization
/// fork. Pedersen VRF absorbs its key commitment before it forks the scalars.
pub(crate) fn vrf_transcript_plain<S: Suite>(
    scheme: DomSep,
    ios: &[VrfIo<S>],
    ad: &[u8],
) -> S::Transcript {
    vrf_transcript(scheme, Ios::plain(ios), ad)
}

/// Merge plain I/O pairs with scalars forked from `t`.
pub(crate) fn delinearize_pairs<S: Suite>(t: &S::Transcript, ios: &[VrfIo<S>]) -> VrfIo<S> {
    merged_pair(Ios::plain(ios), DelinearizeScalars::new(t.clone()))
}

/// Same as [`delinearize_pairs`], but merges the inputs only.
pub(crate) fn delinearize_inputs<S: Suite>(t: &S::Transcript, ios: &[VrfIo<S>]) -> Input<S> {
    merged_input(Ios::plain(ios), DelinearizeScalars::new(t.clone()))
}

/// Prepend the Schnorr pair `(G, Y)` to the I/O list, then build the VRF
/// transcript and the merged input.
pub(crate) fn vrf_transcript_input_with_schnorr<S: Suite>(
    scheme: DomSep,
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Input<S>) {
    vrf_transcript_merged_input(scheme, Ios::with_schnorr(public, ios.as_ref()), ad.as_ref())
}

/// Same as [`vrf_transcript_input_with_schnorr`] but returns the raw
/// delinearization scalars instead of the merged input.
pub(crate) fn vrf_transcript_scalars_with_schnorr<S: Suite>(
    scheme: DomSep,
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    vrf_transcript_scalars(scheme, Ios::with_schnorr(public, ios.as_ref()), ad.as_ref())
}

/// Transcript of the batch verification weights: the scheme tag keeps the
/// Thin and the Pedersen weights in separate hash domains.
pub(crate) fn batch_transcript<S: Suite>(scheme: DomSep) -> S::Transcript {
    let mut t = S::Transcript::new(S::SUITE_ID);
    t.absorb_raw(&[scheme as u8, DomSep::BatchVerify as u8]);
    t
}

/// Whether the key point (`Y` of Tiny and Thin, `Yb` of Pedersen) or a point of
/// an I/O pair is the identity.
pub(crate) fn has_identity<S: Suite>(key: AffinePoint<S>, ios: &[VrfIo<S>]) -> bool {
    key.is_zero() || ios.iter().any(VrfIo::has_identity)
}

/// Point count up to which the Tiny and Thin verifiers expand their equation
/// over the raw pairs. Straus with a one bit window stays cheap up to about
/// five points; above that the merged pair costs less.
const EXPANDED_MAX_POINTS: usize = 5;

/// Left-hand side `s * I_m - c * O_m` of the Tiny and Thin verification
/// equation, with `(G, Y)` prepended as the pair of `zs[0]`.
///
/// With few pairs the merge is skipped: `sum_i (s * z_i) * I_i - (c * z_i) * O_i`
/// runs as one Straus pass over the raw points.
pub(crate) fn schnorr_lhs<S: Suite>(
    public: AffinePoint<S>,
    ios: &[VrfIo<S>],
    zs: &[ScalarField<S>],
    s: ScalarField<S>,
    c: ScalarField<S>,
) -> <AffinePoint<S> as AffineRepr>::Group {
    let ios = Ios::with_schnorr(public, ios);
    let points = 2 * ios.len();
    if points <= EXPANDED_MAX_POINTS {
        let mut bases = Vec::with_capacity(points);
        let mut scalars = Vec::with_capacity(points);
        for (io, z) in ios.iter().zip(zs) {
            bases.push(io.input.0);
            scalars.push(s * z);
            bases.push(io.output.0);
            scalars.push(-(c * z));
        }
        let window = if points <= 3 { 2 } else { 1 };
        short_msm(&bases, &scalars, window)
    } else {
        let merged = merge_ios(ios, zs);
        short_msm(&[merged.input.0, merged.output.0], &[s, -c], 2)
    }
}

/// Projective point that tells whether it has an affine form.
///
/// An off-curve point from the unchecked path can give a twisted Edwards value
/// with Z = 0 that is not the identity. `into_affine` panics on it, and
/// `PartialEq` finds (0, 0, 0, 0) equal to every point. Implemented for the
/// arkworks twisted Edwards and short Weierstrass points.
pub trait ProjectiveZ: CurveGroup {
    /// Returns `true` if the value has an affine form.
    fn has_affine_form(&self) -> bool;

    /// [`CurveGroup::into_affine`] that returns `None` for a value with no
    /// affine form.
    fn into_affine_checked(self) -> Option<Self::Affine> {
        self.has_affine_form().then(|| self.into_affine())
    }
}

impl<P: ark_ec::twisted_edwards::TECurveConfig> ProjectiveZ
    for ark_ec::twisted_edwards::Projective<P>
{
    fn has_affine_form(&self) -> bool {
        !self.z.is_zero()
    }
}

impl<P: ark_ec::short_weierstrass::SWCurveConfig> ProjectiveZ
    for ark_ec::short_weierstrass::Projective<P>
{
    fn has_affine_form(&self) -> bool {
        true // Z = 0 is the identity.
    }
}

/// Challenge after RFC 9381 section 5.4.3: absorb the points, then squeeze
/// [`Suite::CHALLENGE_LEN`] bytes into a scalar.
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

/// Point-to-hash after RFC 9381 section 5.2: the VRF output bytes of an output
/// point.
///
/// `mul_by_cofactor` multiplies the point by the cofactor first, as the RFC
/// does. A point in the prime-order subgroup does not need it.
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

/// Deterministic nonce after RFC 8032 section 5.1.6: hash the secret key to 64
/// bytes, absorb them into the transcript and squeeze the nonce.
///
/// The expanded key and the reduction buffer are zeroized. The hasher states
/// that absorbed the secret are not (see [`crate::utils::DigestXof`]).
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

/// Delinearization scalars from a transcript. The first is `z_0 = 1`, the next
/// ones have [`Suite::SECURITY_PARAMETER`] bits.
pub(crate) struct DelinearizeScalars<S: Suite> {
    transcript: S::Transcript,
    first: bool,
}

impl<S: Suite> DelinearizeScalars<S> {
    /// Stream from a transcript that holds the I/O pairs (see [`absorb_ios`]).
    /// It adds a domain separation tag and starts the squeeze.
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

/// Absorb the I/O pairs after their count as a little-endian `u64`. The count
/// keeps the framing unambiguous also for a point encoding of variable length.
fn absorb_ios<S: Suite>(t: &mut S::Transcript, ios: Ios<'_, S>) {
    let n = ios.len() as u64;
    t.absorb_raw(&n.to_le_bytes());
    for io in ios.iter() {
        t.absorb_serialize(&io.input.0);
        t.absorb_serialize(&io.output.0);
    }
}

/// Pair count at which [`merge_ios`] switches from a fold to an MSM. Below it,
/// the MSM bucket setup costs more than the fold.
pub(crate) const MSM_THRESHOLD: usize = 16;

/// `sum(z_i * P_i)` by fold or MSM. `points` must give `zs.len()` values.
fn merge_points<S: Suite>(
    points: impl Iterator<Item = AffinePoint<S>>,
    zs: &[ScalarField<S>],
) -> <AffinePoint<S> as AffineRepr>::Group {
    if zs.len() < MSM_THRESHOLD {
        let zero = AffinePoint::<S>::zero().into_group();
        points.zip(zs).fold(zero, |acc, (p, z)| acc + p * z)
    } else {
        use ark_ec::VariableBaseMSM;
        type Group<S> = <AffinePoint<S> as AffineRepr>::Group;
        let points: Vec<_> = points.collect();
        Group::<S>::msm_unchecked(&points, zs)
    }
}

/// Merge the I/O pairs with the scalars `zs`. Needs `ios.len() >= 2` and
/// `zs.len() == ios.len()`.
fn merge_ios<S: Suite>(ios: Ios<'_, S>, zs: &[ScalarField<S>]) -> VrfIo<S> {
    let input = merge_points::<S>(ios.iter().map(|io| io.input.0), zs);
    let output = merge_points::<S>(ios.iter().map(|io| io.output.0), zs);
    let norms = CurveGroup::normalize_batch(&[input, output]);
    VrfIo {
        input: Input::from_affine_unchecked(norms[0]),
        output: Output::from_affine_unchecked(norms[1]),
    }
}

/// Merge the inputs only, for the provers. Same conditions as [`merge_ios`].
fn merge_inputs<S: Suite>(ios: Ios<'_, S>, zs: &[ScalarField<S>]) -> Input<S> {
    let input = merge_points::<S>(ios.iter().map(|io| io.input.0), zs);
    Input::from_affine_unchecked(input.into_affine())
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::TestSuite;

    fn sample_ios(n: usize) -> Vec<VrfIo<TestSuite>> {
        let sk = ScalarField::<TestSuite>::from(42u64);
        (0..n as u8)
            .map(|i| {
                let input = TestSuite::data_to_point(&[i]).unwrap();
                let output = (input * sk).into_affine();
                VrfIo {
                    input: Input::from_affine_unchecked(input),
                    output: Output::from_affine_unchecked(output),
                }
            })
            .collect()
    }

    /// Both paths of `schnorr_lhs` (raw pairs and merged pair) must equal the
    /// plain sum, on each side of the threshold.
    #[test]
    fn schnorr_lhs_matches_the_plain_sum() {
        let public = (TestSuite::GENERATOR * ScalarField::<TestSuite>::from(7u64)).into_affine();
        let s = ScalarField::<TestSuite>::from(12345u64);
        let c = ScalarField::<TestSuite>::from(678u64);
        for n in 0..=3 {
            let ios = sample_ios(n);
            let (_, zs) = vrf_transcript_scalars_with_schnorr::<TestSuite>(
                DomSep::TinyVrf,
                public,
                &ios,
                b"ad",
            );
            let zero = AffinePoint::<TestSuite>::zero().into_group();
            let (input, output) = Ios::with_schnorr(public, &ios)
                .iter()
                .zip(&zs)
                .fold((zero, zero), |(i, o), (io, z)| {
                    (i + io.input.0 * z, o + io.output.0 * z)
                });
            let expected = input * s - output * c;
            assert_eq!(schnorr_lhs::<TestSuite>(public, &ios, &zs, s, c), expected);
        }
    }

    /// The merged input of the provers must equal `sum(z_i * I_i)`, or no
    /// verifier accepts the proof. Covers each branch, with and without the
    /// Schnorr pair.
    #[test]
    fn merged_input_matches_the_plain_sum() {
        type Group = <AffinePoint<TestSuite> as AffineRepr>::Group;

        let public = (TestSuite::GENERATOR * ScalarField::<TestSuite>::from(7u64)).into_affine();
        let plain_sum = |ios: Ios<'_, TestSuite>, zs: &[ScalarField<TestSuite>]| {
            ios.iter()
                .zip(zs)
                .map(|(io, z)| io.input.0 * z)
                .sum::<Group>()
                .into_affine()
        };

        for n in [0, 1, MSM_THRESHOLD - 1, MSM_THRESHOLD] {
            let ios = sample_ios(n);

            let t = vrf_transcript_plain::<TestSuite>(DomSep::PedersenVrf, &ios, b"ad");
            let input = delinearize_inputs::<TestSuite>(&t, &ios);
            let zs = DelinearizeScalars::<TestSuite>::new(t).take(n);
            assert_eq!(input.0, plain_sum(Ios::plain(&ios), &zs), "plain, n={n}");

            let schnorr = Ios::with_schnorr(public, &ios);
            let (_, zs) = vrf_transcript_scalars::<TestSuite>(DomSep::TinyVrf, schnorr, b"ad");
            let (_, input) = vrf_transcript_input_with_schnorr::<TestSuite>(
                DomSep::TinyVrf,
                public,
                &ios,
                b"ad",
            );
            assert_eq!(input.0, plain_sum(schnorr, &zs), "schnorr, n={n}");
        }
    }

    /// The Thin batch verifier leaves out `z_0` from its Schnorr terms, so the
    /// stream must start with one.
    #[test]
    fn schnorr_pair_scalar_is_one() {
        use ark_ff::One;

        let public = (TestSuite::GENERATOR * ScalarField::<TestSuite>::from(7u64)).into_affine();
        let ios = sample_ios(2);
        let (_, zs) =
            vrf_transcript_scalars_with_schnorr::<TestSuite>(DomSep::ThinVrf, public, &ios, b"ad");

        assert_eq!(zs.len(), 3);
        assert_eq!(zs[0], ScalarField::<TestSuite>::one());
        assert_ne!(zs[1], ScalarField::<TestSuite>::one());
    }

    /// The Thin and Pedersen batch weights come from transcripts of the same
    /// shape. Only the scheme tag separates them.
    #[test]
    fn batch_transcript_domain_separation() {
        let mut thin = batch_transcript::<TestSuite>(DomSep::ThinVrf);
        let mut pedersen = batch_transcript::<TestSuite>(DomSep::PedersenVrf);
        let mut thin_bytes = [0u8; 32];
        let mut pedersen_bytes = [0u8; 32];
        thin.squeeze_raw(&mut thin_bytes);
        pedersen.squeeze_raw(&mut pedersen_bytes);
        assert_ne!(thin_bytes, pedersen_bytes);
    }

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

        let merged = |scheme| {
            let (_, scalars) = vrf_transcript_base::<TestSuite>(scheme, Ios::plain(&ios), b"foo");
            merged_pair(Ios::plain(&ios), scalars)
        };
        let io_tiny = merged(DomSep::TinyVrf);
        let io_thin = merged(DomSep::ThinVrf);
        let io_ped = merged(DomSep::PedersenVrf);

        assert_ne!(io_tiny, io_thin);
        assert_ne!(io_tiny, io_ped);
        assert_ne!(io_thin, io_ped);
    }

    /// The prover and the verifier share `merge_ios`, so a wrong branch passes
    /// prove and verify. Compare each branch with the plain sum.
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

            let (t, mut scalars) = vrf_transcript_base(DomSep::ThinVrf, Ios::plain(&ios), b"ad");
            let merged = merge_ios(Ios::plain(&ios), &scalars.take(n));

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
    /// `SECURITY_PARAMETER`, and the challenge follows `CHALLENGE_LEN`. A wider
    /// challenge must not widen the delinearization scalars.
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

    /// A twisted Edwards value with Z = 0 that is not the identity has no affine
    /// form. In short Weierstrass, Z = 0 is the identity, a valid value.
    #[test]
    fn projective_z_affine_form() {
        use crate::testing::random_val;
        use ark_ed25519::{
            EdwardsAffine as TeAffine, EdwardsProjective as TeProjective, Fq as TeFq,
        };
        use ark_secp256r1::{Affine as SwAffine, Fq as SwFq, Projective as SwProjective};

        let te_zero = TeFq::zero();
        let te_zero_z = [
            TeProjective::new_unchecked(te_zero, te_zero, te_zero, te_zero),
            TeProjective::new_unchecked(
                TeFq::from(3u64),
                TeFq::from(5u64),
                TeFq::from(7u64),
                te_zero,
            ),
        ];
        for te_value in te_zero_z {
            assert!(!te_value.is_zero());
            assert!(!te_value.has_affine_form());
            assert_eq!(te_value.into_affine_checked(), None);
        }
        let te_point = random_val::<TeProjective>(None);
        assert_eq!(te_point.into_affine_checked(), Some(te_point.into_affine()));
        assert_eq!(
            TeProjective::zero().into_affine_checked(),
            Some(TeAffine::zero())
        );

        let sw_zero_z =
            SwProjective::new_unchecked(SwFq::from(3u64), SwFq::from(5u64), SwFq::zero());
        assert!(sw_zero_z.is_zero());
        assert_eq!(sw_zero_z.into_affine_checked(), Some(SwAffine::zero()));
        let sw_point = random_val::<SwProjective>(None);
        assert_eq!(sw_point.into_affine_checked(), Some(sw_point.into_affine()));
    }
}
