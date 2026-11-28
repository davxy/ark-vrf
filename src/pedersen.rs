//! # Pedersen VRF
//!
//! Key-hiding VRF after PedVRF in section 4 of
//! [BCHSV23](https://eprint.iacr.org/2023/002). A Pedersen commitment to the
//! secret key replaces the public key, so the proof does not show the key. Ring
//! VRF builds on it.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_ec::CurveGroup;
//! use ark_vrf::pedersen::{PedersenSuite, Proof};
//! use ark_vrf::suites::bandersnatch::*;
//!
//! let sk = SecretKey::from_seed([0; 32]);
//! let pk = sk.public_key();
//! let input = Input::new(b"example input").unwrap();
//! let io = sk.io_pair(input);
//!
//! // Proving (`sk.prove_pedersen(io, b"aux data")` is the same)
//! let (proof, blinding) = Proof::prove(io, b"aux data", &sk);
//!
//! // Verification
//! let res = proof.verify(io, b"aux data");
//!
//! // Unblinding: verify the proof was created using a specific public key
//! let expected = (pk.into_affine() + blinding.mul_point(BandersnatchSha512Ell2::BLINDING_BASE)).into_affine();
//! assert_eq!(proof.key_commitment(), expected);
//! ```

use crate::Suite;
use crate::utils;
use crate::utils::canonical::CanonicalDeserializeStrict;
use crate::utils::common::{DomSep, ProjectiveZ};
use crate::utils::straus::short_msm;
use crate::*;
use ark_ec::VariableBaseMSM;

/// Seed hashed to curve to produce [`PedersenSuite::BLINDING_BASE`] in built-in suites.
pub const PEDERSEN_BLINDING_BASE_SEED: &[u8] = b"pedersen-blinding";

/// Suites with Pedersen VRF.
pub trait PedersenSuite: Suite {
    /// Blinding base `B`. Nobody may know its discrete log to the generator. The
    /// built-in suites hash [`PEDERSEN_BLINDING_BASE_SEED`] to the curve.
    const BLINDING_BASE: AffinePoint<Self>;

    /// Blinding factor from the secret key and the transcript. The default
    /// derives it with [`Suite::nonce`].
    fn blinding(sk: &SecretScalar<Self>, mut transcript: Self::Transcript) -> SecretScalar<Self> {
        transcript.absorb_raw(&[DomSep::PedersenBlinding as u8]);
        Self::nonce(sk, transcript)
    }
}

#[inline(always)]
fn vrf_transcript<S: PedersenSuite>(ios: &[IoPair<S>], ad: &[u8]) -> S::Transcript {
    utils::vrf_transcript_plain(DomSep::PedersenVrf, ios, ad)
}

/// Absorb the key commitment, then merge the I/O pairs.
///
/// The key commitment is the only binding to the key, so the scalars must
/// depend on it. With scalars drawn before it, a prover can choose its key
/// after the scalars and prove pairs that the key did not produce.
fn merge_with_key_commitment<S: PedersenSuite>(
    t: &mut S::Transcript,
    pk_com: &AffinePoint<S>,
    ios: &[IoPair<S>],
) -> IoPair<S> {
    t.absorb_serialize(pk_com);
    utils::delinearize_pairs(t, ios)
}

/// Same as [`merge_with_key_commitment`], but merges the inputs only.
fn merge_inputs_with_key_commitment<S: PedersenSuite>(
    t: &mut S::Transcript,
    pk_com: &AffinePoint<S>,
    ios: &[IoPair<S>],
) -> Input<S> {
    t.absorb_serialize(pk_com);
    utils::delinearize_inputs(t, ios)
}

/// Pedersen VRF proof:
/// - the key commitment `Yb = x * G + b * B`,
/// - the nonce commitments `R = k * G + kb * B` and `Ok = k * I_m`,
/// - the responses `s = k + c * x` and `sb = kb + c * b`.
///
/// Decoding follows the rules in [`PointWrapper`].
#[derive(Debug, Clone, CanonicalSerialize)]
pub struct Proof<S: PedersenSuite> {
    pub(crate) pk_com: AffinePoint<S>,
    pub(crate) r: AffinePoint<S>,
    pub(crate) ok: AffinePoint<S>,
    pub(crate) s: ScalarField<S>,
    pub(crate) sb: ScalarField<S>,
}

impl<S: PedersenSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let pk_com = AffinePoint::<S>::deserialize_strict(&mut reader, compress, validate)?;
        let r = AffinePoint::<S>::deserialize_strict(&mut reader, compress, validate)?;
        let ok = AffinePoint::<S>::deserialize_strict(&mut reader, compress, validate)?;
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let sb = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        Ok(Proof {
            pk_com,
            r,
            ok,
            s,
            sb,
        })
    }
}

impl<S: PedersenSuite> ark_serialize::Valid for Proof<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pk_com.check()?;
        self.r.check()?;
        self.ok.check()?;
        self.s.check()?;
        self.sb.check()
    }
}

impl<S: PedersenSuite> Proof<S> {
    /// Get the public key commitment `Yb`.
    pub fn key_commitment(&self) -> AffinePoint<S> {
        self.pk_com
    }
}

impl<S: PedersenSuite> Proof<S> {
    /// Prove the VRF I/O pairs `ios` with the additional data `ad`.
    ///
    /// Also returns the blinding factor `b`. It is secret: with it, anybody can
    /// open `Yb` to the public key.
    pub fn prove(
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        sk: &SecretKey<S>,
    ) -> (Self, SecretScalar<S>) {
        let ios = ios.as_ref();
        let mut t = vrf_transcript::<S>(ios, ad.as_ref());

        // `k` and `kb` absorb `Yb`, so a hedged `b` also hedges them.
        let blinding = S::blinding(sk.scalar(), sk.nonce_transcript(&t));

        let bb = blinding.mul_point(S::BLINDING_BASE);
        let pk_com = (sk.public_key().0.into_group() + bb).into_affine();

        let input = merge_inputs_with_key_commitment::<S>(&mut t, &pk_com, ios);

        // Nonces from T.fork(). The extra byte is temporary. Releases before
        // 0.7.0 get the same nonces without it, and a different challenge, which
        // discloses the secret key. Remove it at the next major release.
        let mut fork = t.clone();
        if ios.len() > 1 {
            fork.absorb_raw(&[0xff]);
        }
        let k = S::nonce(sk.scalar(), fork.clone());
        let kb = S::nonce(&blinding, fork);

        let r = k.mul_point(S::GENERATOR) + kb.mul_point(S::BLINDING_BASE);
        let ok = k.mul_point(input.0);

        let norms = CurveGroup::normalize_batch(&[r, ok]);
        let (r, ok) = (norms[0], norms[1]);

        let c = S::challenge(&[&r, &ok], t);

        let s = k.response(c, sk.scalar());
        let sb = kb.response(c, &blinding);

        let proof = Proof {
            pk_com,
            r,
            ok,
            s,
            sb,
        };
        (proof, blinding)
    }

    /// Verify the proof for the VRF I/O pairs `ios` and the additional data `ad`.
    ///
    /// Returns `Error::InvalidData` if the key commitment or a point of `ios` is
    /// the identity, and `Error::VerificationFailure` if the proof is not valid.
    /// Subgroup membership is not checked (see [`PointWrapper`]).
    pub fn verify(&self, ios: impl AsRef<[IoPair<S>]>, ad: impl AsRef<[u8]>) -> Result<(), Error> {
        let Proof {
            pk_com,
            r,
            ok,
            s,
            sb,
        } = self;

        let ios = ios.as_ref();
        if utils::has_identity(*pk_com, ios) {
            return Err(Error::InvalidData);
        }

        let mut t = vrf_transcript::<S>(ios, ad.as_ref());

        let io = merge_with_key_commitment::<S>(&mut t, pk_com, ios);

        let c = S::challenge(&[r, ok], t);

        let neg_c = -c;

        // s * I_m - c * O_m == Ok
        let lhs1 = short_msm(&[io.input.0, io.output.0], &[*s, neg_c], 2);
        if !lhs1.has_affine_form() || lhs1 != ok.into_group() {
            return Err(Error::VerificationFailure);
        }

        // s * G + sb * B - c * Yb == R
        let lhs2 = short_msm(
            &[S::GENERATOR, S::BLINDING_BASE, *pk_com],
            &[*s, *sb, neg_c],
            2,
        );
        if !lhs2.has_affine_form() || lhs2 != r.into_group() {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

impl<S: PedersenSuite> SecretKey<S> {
    /// Generate a Pedersen VRF proof. Same as [`Proof::prove`].
    pub fn prove_pedersen(
        &self,
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, SecretScalar<S>) {
        Proof::prove(ios, ad, self)
    }
}

/// Pedersen VRF proof prepared for [`BatchVerifier`].
pub struct BatchItem<S: PedersenSuite> {
    c: ScalarField<S>,
    input: AffinePoint<S>,
    output: AffinePoint<S>,
    pk_com: AffinePoint<S>,
    r: AffinePoint<S>,
    ok: AffinePoint<S>,
    s: ScalarField<S>,
    sb: ScalarField<S>,
    /// Whether the key commitment or a pair is the identity. The merged pair
    /// cannot show it: it is also the identity when there is no pair.
    identity: bool,
}

impl<S: PedersenSuite> BatchItem<S> {
    /// Prepare a proof for batch verification. With one I/O pair this only
    /// hashes. It can run in parallel.
    pub fn new(ios: impl AsRef<[IoPair<S>]>, ad: impl AsRef<[u8]>, proof: &Proof<S>) -> Self {
        let ios = ios.as_ref();
        let identity = utils::has_identity(proof.pk_com, ios);
        let mut t = vrf_transcript::<S>(ios, ad.as_ref());
        let io = merge_with_key_commitment::<S>(&mut t, &proof.pk_com, ios);
        let c = S::challenge(&[&proof.r, &proof.ok], t);
        Self {
            c,
            input: io.input.0,
            output: io.output.0,
            pk_com: proof.pk_com,
            r: proof.r,
            ok: proof.ok,
            s: proof.s,
            sb: proof.sb,
            identity,
        }
    }
}

/// Batch verifier for Pedersen VRF proofs.
pub struct BatchVerifier<S: PedersenSuite> {
    items: Vec<BatchItem<S>>,
}

impl<S: PedersenSuite> Default for BatchVerifier<S> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}

impl<S: PedersenSuite> BatchVerifier<S> {
    /// Create a new empty batch verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a previously prepared item into the batch.
    pub fn push_prepared(&mut self, item: BatchItem<S>) {
        self.items.push(item);
    }

    /// Prepare and push a proof in one step.
    pub fn push(&mut self, ios: impl AsRef<[IoPair<S>]>, ad: impl AsRef<[u8]>, proof: &Proof<S>) {
        self.push_prepared(BatchItem::new(ios, ad, proof));
    }

    /// Verify all the proofs with one multi-scalar multiplication.
    ///
    /// Returns `Error::InvalidData` if a key commitment or a point of an I/O
    /// pair is the identity, and `Error::VerificationFailure` if a proof is not
    /// valid. Subgroup membership is not checked (see [`PointWrapper`]).
    pub fn verify(&self) -> Result<(), Error> {
        let items = &self.items;
        if items.is_empty() {
            return Ok(());
        }

        // Rejected here rather than in `BatchItem::new`, which cannot fail.
        if items.iter().any(|item| item.identity) {
            return Err(Error::InvalidData);
        }

        let n = items.len();

        // The weights depend on all the proofs. `c` commits to the points and
        // `ad`, so the responses complete the proof.
        let mut t = utils::batch_transcript::<S>(DomSep::PedersenVrf);
        for e in items {
            t.absorb_serialize(&e.c);
            t.absorb_serialize(&e.s);
            t.absorb_serialize(&e.sb);
        }
        // Weights of SECURITY_PARAMETER bits are enough for Schwartz-Zippel and
        // make the MSM shorter than full-width scalars.
        let random_scalars: Vec<(ScalarField<S>, ScalarField<S>)> = (0..n)
            .map(|_| {
                (
                    utils::weight_scalar::<S>(&mut t),
                    utils::weight_scalar::<S>(&mut t),
                )
            })
            .collect();

        // Proof i, weighted by t_i and u_i:
        //   t_i * (c_i * O_i + Ok_i - s_i * I_i) = 0
        //   u_i * (c_i * Yb_i + R_i - s_i * G - sb_i * B) = 0
        // All proofs share the G and B bases.
        let mut bases = Vec::with_capacity(5 * n + 2);
        let mut scalars = Vec::with_capacity(5 * n + 2);

        let mut g_scalar = ScalarField::<S>::zero();
        let mut b_scalar = ScalarField::<S>::zero();

        for (e, (t, u)) in items.iter().zip(random_scalars.iter()) {
            bases.push(e.output);
            scalars.push(*t * e.c);

            bases.push(e.ok);
            scalars.push(*t);

            bases.push(e.input);
            scalars.push(-(*t * e.s));

            bases.push(e.pk_com);
            scalars.push(*u * e.c);

            bases.push(e.r);
            scalars.push(*u);

            g_scalar += *u * e.s;
            b_scalar += *u * e.sb;
        }

        bases.push(S::GENERATOR);
        scalars.push(-g_scalar);

        bases.push(S::BLINDING_BASE);
        scalars.push(-b_scalar);

        let res = <S::Affine as AffineRepr>::Group::msm_unchecked(&bases, &scalars);
        if !res.is_zero() {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::testing::{self as common, CheckPoint, SuiteExt, TEST_SEED, random_val};

    pub fn prove_verify<S: PedersenSuite>() {
        let sk = SecretKey::<S>::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(None));
        let io = sk.io_pair(input);

        let (proof, blinding) = sk.prove_pedersen(io, b"foo");
        let res = proof.verify(io, b"foo");
        assert!(res.is_ok());

        assert_eq!(
            proof.key_commitment(),
            (sk.public_key().0 + S::BLINDING_BASE * *blinding.expose_secret()).into()
        );
    }

    pub fn batch_verify<S: PedersenSuite>() {
        use pedersen::{BatchItem, BatchVerifier};

        let sk = SecretKey::<S>::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(None));
        let io = sk.io_pair(input);

        let (proof1, _) = sk.prove_pedersen(io, b"foo");
        let (proof2, _) = sk.prove_pedersen(io, b"bar");

        assert!(proof1.verify(io, b"foo").is_ok());
        assert!(proof2.verify(io, b"bar").is_ok());

        let mut batch = BatchVerifier::new();
        batch.push(io, b"foo", &proof1);
        batch.push(io, b"bar", &proof2);
        assert!(batch.verify().is_ok());

        let mut batch = BatchVerifier::new();
        let entry1 = BatchItem::new(io, b"foo", &proof1);
        let entry2 = BatchItem::new(io, b"bar", &proof2);
        batch.push_prepared(entry1);
        batch.push_prepared(entry2);
        assert!(batch.verify().is_ok());

        let batch = BatchVerifier::<S>::new();
        assert!(batch.verify().is_ok());

        let mut batch = BatchVerifier::new();
        batch.push(io, b"foo", &proof1);
        batch.push(io, b"wrong", &proof2);
        assert!(batch.verify().is_err());
    }

    /// N=1 slice produces same proof as passing a single `IoPair`.
    pub fn prove_verify_multi_single<S: PedersenSuite>() {
        let sk = SecretKey::<S>::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(None));
        let io = sk.io_pair(input);

        let (proof_single, blinding_single) = sk.prove_pedersen(io, b"foo");
        let (proof_slice, blinding_slice) = sk.prove_pedersen([io], b"foo");

        let encode = |p: &pedersen::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));
        assert_eq!(
            blinding_single.expose_secret(),
            blinding_slice.expose_secret()
        );
        assert!(proof_slice.verify(io, b"foo").is_ok());
        assert!(proof_single.verify([io], b"foo").is_ok());
    }

    /// N=3 multi proof: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: PedersenSuite>() {
        let sk = SecretKey::<S>::from_seed(TEST_SEED);

        let mut ios: Vec<IoPair<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                sk.io_pair(input)
            })
            .collect();
        ios.push(IoPair {
            input: Input::from_affine_unchecked(S::Affine::generator()),
            output: Output::from_affine_unchecked(sk.public_key().0),
        });

        let (proof, _) = sk.prove_pedersen(&ios[..], b"bar");
        assert!(proof.verify(&ios[..], b"bar").is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[1].output = sk.output(ios[0].input);
        assert!(proof.verify(&bad_ios[..], b"bar").is_err());

        let mut bad_ios = ios.clone();
        bad_ios[0].input = ios[1].input;
        assert!(proof.verify(&bad_ios[..], b"bar").is_err());

        assert!(proof.verify(&ios[..], b"baz").is_err());
    }

    /// With no VRF pairs, the proof is a Schnorr signature over `ad`.
    pub fn prove_verify_multi_empty<S: PedersenSuite>() {
        let sk = SecretKey::<S>::from_seed(TEST_SEED);

        let ios: [IoPair<S>; 0] = [];
        let (proof, _) = sk.prove_pedersen(ios, b"bar");

        assert!(proof.verify(ios, b"bar").is_ok());

        assert!(proof.verify(ios, b"baz").is_err());
    }

    /// One proof must have one encoding. With no I/O pairs, `Ok` is the
    /// identity, which arkworks reads from several byte strings.
    pub fn proof_encoding_is_canonical<S: PedersenSuite>() {
        use ark_serialize::Compress;

        let sk = SecretKey::<S>::from_seed(TEST_SEED);
        let ios: [IoPair<S>; 0] = [];
        let (proof, _) = sk.prove_pedersen(ios, b"foo");
        assert!(proof.ok.is_zero());

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(decoded.verify(ios, b"foo").is_ok());
        let mut reencoded = Vec::new();
        decoded.serialize_compressed(&mut reencoded).unwrap();
        assert_eq!(bytes, reencoded);

        let point_len = proof.pk_com.compressed_size();
        let ok_range = 2 * point_len..3 * point_len;
        let aliases = common::assert_aliases_rejected::<AffinePoint<S>>(
            &bytes,
            ok_range,
            Compress::Yes,
            |bytes| {
                Proof::<S>::deserialize_compressed(bytes).is_ok()
                    || common::decodes_inside_vec::<Proof<S>>(bytes, Compress::Yes)
            },
        );
        assert!(!aliases.is_empty());
    }

    /// Runs the MSM branch of `merge_ios` (`MSM_THRESHOLD` pairs) through prove,
    /// verify and batch verify.
    pub fn prove_verify_multi_msm<S: PedersenSuite>() {
        use crate::utils::common::MSM_THRESHOLD;
        use pedersen::BatchVerifier;

        let sk = SecretKey::<S>::from_seed(TEST_SEED);
        let ios: Vec<IoPair<S>> = (0..MSM_THRESHOLD as u8)
            .map(|i| sk.io_pair(Input::new(&[i]).unwrap()))
            .collect();

        let (proof, _) = sk.prove_pedersen(&ios[..], b"msm");
        assert!(proof.verify(&ios[..], b"msm").is_ok());
        let mut batch = BatchVerifier::new();
        batch.push(&ios[..], b"msm", &proof);
        assert!(batch.verify().is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[MSM_THRESHOLD - 1].output = ios[0].output;
        assert!(proof.verify(&bad_ios[..], b"msm").is_err());
        let mut batch = BatchVerifier::new();
        batch.push(&bad_ios[..], b"msm", &proof);
        assert!(batch.verify().is_err());
    }

    /// `(0, 0)` satisfies `O = x * I` for every key, so it binds its output to no
    /// signer. The second case hides it behind a valid pair, where the merged
    /// pair does not show it.
    pub fn identity_io_pair_rejected<S: PedersenSuite>() {
        use pedersen::BatchVerifier;

        let identity_io = IoPair::<S> {
            input: Input::from_affine_unchecked(AffinePoint::<S>::zero()),
            output: Output::from_affine_unchecked(AffinePoint::<S>::zero()),
        };

        for seed in [TEST_SEED, [0x11; 32]] {
            let sk = SecretKey::<S>::from_seed(seed);

            let (proof, _) = sk.prove_pedersen([identity_io], b"forgery");
            assert!(proof.verify([identity_io], b"forgery").is_err());

            let mut batch = BatchVerifier::new();
            batch.push([identity_io], b"forgery", &proof);
            assert!(batch.verify().is_err());

            let good_io = sk.io_pair(Input::new(b"good").unwrap());
            let ios = [good_io, identity_io];
            let (proof, _) = sk.prove_pedersen(ios, b"forgery");
            assert!(proof.verify(ios, b"forgery").is_err());

            let mut batch = BatchVerifier::new();
            batch.push(ios, b"forgery", &proof);
            assert!(batch.verify().is_err());
        }
    }

    /// `Yb = 0` opens to the public `(x, b) = (0, 0)`, so anybody can build this
    /// proof. Both equations hold, so both verifiers must reject it explicitly.
    pub fn identity_key_commitment_rejected<S: PedersenSuite>() {
        use pedersen::BatchVerifier;

        let ios: [IoPair<S>; 0] = [];
        let ad = b"forgery";

        let pk_com = AffinePoint::<S>::zero();
        let mut t = vrf_transcript::<S>(&ios, ad);
        let io = merge_with_key_commitment::<S>(&mut t, &pk_com, &ios);

        let k = ScalarField::<S>::from(7u64);
        let kb = ScalarField::<S>::from(11u64);
        let r = (S::GENERATOR * k + S::BLINDING_BASE * kb).into_affine();
        let ok = (io.input.0 * k).into_affine();

        let proof = Proof {
            pk_com,
            r,
            ok,
            s: k,
            sb: kb,
        };

        assert!(proof.verify(ios, ad).is_err());

        let mut batch = BatchVerifier::new();
        batch.push(ios, ad, &proof);
        assert!(batch.verify().is_err());
    }

    /// An off-curve `(0, 0)` key commitment or output, which only the unchecked
    /// path lets through, gives a side of an equation `(0, 0, 0, 0)` on a
    /// twisted Edwards suite, which arkworks finds equal to every point. If
    /// single verify accepts it, anybody proves with no key, a signer gets a
    /// second output for each input, and single and batch verify disagree.
    pub fn off_curve_point_rejected<S: PedersenSuite>() {
        use ark_ff::One;
        use pedersen::BatchVerifier;

        let assert_rejected = |ios: &[IoPair<S>], proof: &Proof<S>| {
            assert!(proof.verify(ios, b"bar").is_err());
            let mut batch = BatchVerifier::new();
            batch.push(ios, b"bar", proof);
            assert!(batch.verify().is_err());
        };
        let off_curve = common::off_curve_point::<S>();

        let keyless = Proof::<S> {
            pk_com: off_curve,
            r: S::GENERATOR,
            ok: AffinePoint::<S>::zero(),
            s: ScalarField::<S>::one(),
            sb: ScalarField::<S>::one(),
        };
        assert_rejected(&[], &keyless);

        let sk = SecretKey::<S>::from_seed(TEST_SEED);
        let off_curve_io = IoPair {
            input: Input::new(b"foo").unwrap(),
            output: Output::from_affine_unchecked(off_curve),
        };
        let good_io = sk.io_pair(Input::new(b"good").unwrap());
        for ios in [&[off_curve_io][..], &[good_io, off_curve_io][..]] {
            let (proof, _) = sk.prove_pedersen(ios, b"bar");
            assert_rejected(ios, &proof);
        }
    }

    /// A key chosen after the delinearization weights must not prove pairs that
    /// it did not produce. The attacker gives one input two outputs, takes the
    /// weights from the pairs and `ad`, and solves for the key. If a verifier
    /// accepts, one key has two outputs for one input.
    pub fn key_chosen_after_weights_rejected<S: PedersenSuite>() {
        use crate::utils::common::DelinearizeScalars;
        use pedersen::BatchVerifier;

        let ad = b"forgery";
        let input = Input::<S>::new(b"input").unwrap();
        let (b0, b1) = (
            ScalarField::<S>::from(1111u64),
            ScalarField::<S>::from(2222u64),
        );
        let pair = |factor: ScalarField<S>| IoPair {
            input,
            output: Output::from_affine_unchecked((input.0 * factor).into_affine()),
        };
        let ios = [pair(b0), pair(b1)];

        let t = vrf_transcript::<S>(&ios, ad);
        let z = DelinearizeScalars::<S>::new(t).take(2);

        let x = (z[0] * b0 + z[1] * b1) / (z[0] + z[1]);
        let (proof, _) = SecretKey::<S>::from_scalar(x).prove_pedersen(ios, ad);

        assert!(proof.verify(ios, ad).is_err());

        let mut batch = BatchVerifier::new();
        batch.push(ios, ad, &proof);
        assert!(batch.verify().is_err());
    }

    /// Two proofs of one signer with no I/O pairs on the same `ad` must have
    /// different key commitments. An observer links proofs with the same `Yb`,
    /// and names the signer of two such ring proofs in two different rings.
    #[cfg(feature = "hedged-nonce")]
    pub fn key_commitment_unlinkable<S: PedersenSuite>() {
        let sk = SecretKey::<S>::from_seed(TEST_SEED).with_hedged_nonce();
        let ios: [IoPair<S>; 0] = [];
        let (first, _) = sk.prove_pedersen(ios, b"ad");
        let (second, _) = sk.prove_pedersen(ios, b"ad");
        assert!(first.verify(ios, b"ad").is_ok());
        assert!(second.verify(ios, b"ad").is_ok());
        assert_ne!(first.key_commitment(), second.key_commitment());
    }

    pub fn blinding_base_check<S: PedersenSuite>()
    where
        AffinePoint<S>: CheckPoint,
    {
        assert_eq!(
            S::BLINDING_BASE,
            S::data_to_point(PEDERSEN_BLINDING_BASE_SEED).unwrap()
        );
        assert!(S::BLINDING_BASE.check(true).is_ok());
    }

    #[macro_export]
    macro_rules! pedersen_suite_tests {
        ($suite:ty) => {
            mod pedersen {
                use super::*;

                #[test]
                fn proof_encoding_is_canonical() {
                    $crate::pedersen::testing::proof_encoding_is_canonical::<$suite>()
                }

                #[test]
                fn prove_verify() {
                    $crate::pedersen::testing::prove_verify::<$suite>();
                }

                #[test]
                fn prove_verify_multi_single() {
                    $crate::pedersen::testing::prove_verify_multi_single::<$suite>();
                }

                #[test]
                fn prove_verify_multi() {
                    $crate::pedersen::testing::prove_verify_multi::<$suite>();
                }

                #[test]
                fn prove_verify_multi_empty() {
                    $crate::pedersen::testing::prove_verify_multi_empty::<$suite>();
                }

                #[test]
                fn prove_verify_multi_msm() {
                    $crate::pedersen::testing::prove_verify_multi_msm::<$suite>();
                }

                #[test]
                fn batch_verify() {
                    $crate::pedersen::testing::batch_verify::<$suite>();
                }

                #[test]
                fn identity_io_pair_rejected() {
                    $crate::pedersen::testing::identity_io_pair_rejected::<$suite>();
                }

                #[test]
                fn identity_key_commitment_rejected() {
                    $crate::pedersen::testing::identity_key_commitment_rejected::<$suite>();
                }

                #[test]
                fn off_curve_point_rejected() {
                    $crate::pedersen::testing::off_curve_point_rejected::<$suite>();
                }

                #[test]
                fn key_chosen_after_weights_rejected() {
                    $crate::pedersen::testing::key_chosen_after_weights_rejected::<$suite>();
                }

                #[cfg(feature = "hedged-nonce")]
                #[test]
                fn key_commitment_unlinkable() {
                    $crate::pedersen::testing::key_commitment_unlinkable::<$suite>();
                }

                #[test]
                fn blinding_base_check() {
                    $crate::pedersen::testing::blinding_base_check::<$suite>();
                }

                $crate::test_vectors!($crate::pedersen::testing::TestVector<$suite>);
            }
        };
    }

    pub struct TestVector<S: PedersenSuite> {
        pub base: common::TestVector<S>,
        pub blind: ScalarField<S>,
        pub proof: Proof<S>,
    }

    impl<S: PedersenSuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TestVector")
                .field("base", &self.base)
                .field("blinding", &self.blind)
                .field("proof_pk_com", &self.proof.pk_com)
                .field("proof_r", &self.proof.r)
                .field("proof_ok", &self.proof.ok)
                .field("proof_s", &self.proof.s)
                .field("proof_sb", &self.proof.sb)
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: PedersenSuite + SuiteExt + std::fmt::Debug,
    {
        fn name() -> String {
            S::SUITE_NAME.to_string() + "_pedersen"
        }

        fn new(comment: &str, seed: &[u8; 32], alpha: &[u8], ad: &[u8]) -> Self {
            let base = common::TestVector::new(comment, seed, alpha, ad);
            let io = IoPair {
                input: Input::<S>::from_affine_unchecked(base.h),
                output: Output::from_affine_unchecked(base.gamma),
            };
            let sk = SecretKey::from_scalar(base.sk);
            let (proof, blind) = sk.prove_pedersen(io, ad);
            let blind = *blind.expose_secret();
            Self { base, blind, proof }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let blind = common::scalar_decode::<S>(&map.get_bytes("blinding"));
            let pk_com = common::point_decode::<S>(&map.get_bytes("proof_pk_com")).unwrap();
            let r = common::point_decode::<S>(&map.get_bytes("proof_r")).unwrap();
            let ok = common::point_decode::<S>(&map.get_bytes("proof_ok")).unwrap();
            let s = common::scalar_decode::<S>(&map.get_bytes("proof_s"));
            let sb = common::scalar_decode::<S>(&map.get_bytes("proof_sb"));
            let proof = Proof {
                pk_com,
                r,
                ok,
                s,
                sb,
            };
            Self { base, blind, proof }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let items = [
                (
                    "blinding",
                    hex::encode(common::scalar_encode::<S>(&self.blind)),
                ),
                (
                    "proof_pk_com",
                    hex::encode(common::point_encode::<S>(&self.proof.pk_com)),
                ),
                (
                    "proof_r",
                    hex::encode(common::point_encode::<S>(&self.proof.r)),
                ),
                (
                    "proof_ok",
                    hex::encode(common::point_encode::<S>(&self.proof.ok)),
                ),
                (
                    "proof_s",
                    hex::encode(common::scalar_encode::<S>(&self.proof.s)),
                ),
                (
                    "proof_sb",
                    hex::encode(common::scalar_encode::<S>(&self.proof.sb)),
                ),
            ];
            let mut map = self.base.to_map();
            items.into_iter().for_each(|(name, value)| {
                map.0.insert(name.to_string(), value);
            });
            map
        }

        fn run(&self) {
            self.base.run();
            let io = IoPair {
                input: Input::<S>::from_affine_unchecked(self.base.h),
                output: Output::from_affine_unchecked(self.base.gamma),
            };
            let sk = SecretKey::from_scalar(self.base.sk);
            let (proof, blind) = sk.prove_pedersen(io, &self.base.ad);
            assert_eq!(
                &self.blind,
                blind.expose_secret(),
                "Blinding factor mismatch"
            );
            assert_eq!(self.proof.pk_com, proof.pk_com, "Proof pkb mismatch");
            assert_eq!(self.proof.r, proof.r, "Proof r mismatch");
            assert_eq!(self.proof.ok, proof.ok, "Proof ok mismatch");
            assert_eq!(self.proof.s, proof.s, "Proof s mismatch");
            assert_eq!(self.proof.sb, proof.sb, "Proof sb mismatch");

            assert!(proof.verify(io, &self.base.ad).is_ok());
        }
    }
}
