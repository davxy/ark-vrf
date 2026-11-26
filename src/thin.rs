//! # Thin VRF
//!
//! VRF-AD with an `(R, s)` proof. The proof holds the nonce commitment instead
//! of the challenge, so it is larger than a Tiny VRF proof but supports batch
//! verification.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::thin::Proof;
//!
//! let secret = Secret::from_seed([0; 32]);
//! let public = secret.public();
//! let input = Input::new(b"example input").unwrap();
//! let io = secret.vrf_io(input);
//!
//! // Proving
//! let proof = Proof::prove(io, b"aux data", &secret);
//!
//! // Verification
//! let result = proof.verify(io, b"aux data", &public);
//!
//! // The same, as methods of the keys
//! let proof = secret.prove_thin(io, b"aux data");
//! let result = public.verify_thin(io, b"aux data", &proof);
//! ```

use crate::{
    utils::canonical::CanonicalDeserializeStrict, utils::common::DomSep,
    utils::common::ProjectiveZ, utils::weight_scalar, *,
};

/// Suites with Thin VRF. Every [`Suite`] implements it.
pub trait ThinSuite: Suite {}

impl<T> ThinSuite for T where T: Suite {}

/// Thin VRF proof: the nonce commitment `R = k * I_m` and the response
/// `s = k + c * x`.
///
/// Decoding follows the rules in [`PointWrapper`].
#[derive(Debug, Clone, CanonicalSerialize)]
pub struct Proof<S: ThinSuite> {
    pub(crate) r: AffinePoint<S>,
    pub(crate) s: ScalarField<S>,
}

impl<S: ThinSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let r = AffinePoint::<S>::deserialize_strict(&mut reader, compress, validate)?;
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        Ok(Proof { r, s })
    }
}

impl<S: ThinSuite> ark_serialize::Valid for Proof<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.r.check()?;
        self.s.check()
    }
}

#[inline(always)]
fn vrf_transcript_input<S: ThinSuite>(
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Input<S>) {
    utils::vrf_transcript_input_with_schnorr(DomSep::ThinVrf, public, ios, ad)
}

#[inline(always)]
fn vrf_transcript_scalars<S: ThinSuite>(
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    utils::vrf_transcript_scalars_with_schnorr(DomSep::ThinVrf, public, ios, ad)
}

impl<S: ThinSuite> Proof<S> {
    /// Prove the VRF I/O pairs `ios` with the additional data `ad`.
    pub fn prove(ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>, secret: &Secret<S>) -> Self {
        let (t, input) = vrf_transcript_input::<S>(secret.public.0, ios, ad);

        let mut k = S::nonce(&secret.scalar, t.clone());
        let r = smul!(input.0, k).into_affine();
        let c = S::challenge(&[&r], t);

        let mut cx = c * secret.scalar;
        let s = k + cx;
        k.zeroize();
        cx.zeroize();

        Proof { r, s }
    }

    /// Verify the proof for the VRF I/O pairs `ios`, the additional data `ad`
    /// and the key `public`.
    ///
    /// Returns `Error::InvalidData` if the key or a point of `ios` is the
    /// identity, and `Error::VerificationFailure` if the proof is not valid.
    /// Subgroup membership is not checked (see [`PointWrapper`]).
    pub fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        public: &Public<S>,
    ) -> Result<(), Error> {
        let ios = ios.as_ref();
        if utils::has_identity(public.0, ios) {
            return Err(Error::InvalidData);
        }

        let Proof { r, s } = self;
        let (t, zs) = vrf_transcript_scalars::<S>(public.0, ios, ad);
        let c = S::challenge(&[r], t);

        // s * I_m - c * O_m == R
        let lhs = utils::schnorr_lhs::<S>(public.0, ios, &zs, *s, c);
        if !lhs.has_affine_form() || lhs != r.into_group() {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

impl<S: ThinSuite> Secret<S> {
    /// Generate a Thin VRF proof. Same as [`Proof::prove`].
    pub fn prove_thin(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S> {
        Proof::prove(ios, ad, self)
    }
}

impl<S: ThinSuite> Public<S> {
    /// Verify a Thin VRF proof. Same as [`Proof::verify`].
    pub fn verify_thin(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        proof.verify(ios, ad, self)
    }
}

/// Thin VRF proof prepared for [`BatchVerifier`].
pub struct BatchItem<S: ThinSuite> {
    c: ScalarField<S>,
    pk: Public<S>,
    ios: Vec<VrfIo<S>>,
    zs: Vec<ScalarField<S>>,
    r: AffinePoint<S>,
    s: ScalarField<S>,
}

impl<S: ThinSuite> BatchItem<S> {
    /// Prepare a proof for batch verification. This only hashes, so it is cheap
    /// and can run in parallel.
    pub fn new(
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        public: &Public<S>,
    ) -> Self {
        let ios = ios.as_ref();
        let (t, zs) = vrf_transcript_scalars::<S>(public.0, ios, ad);
        let c = S::challenge(&[&proof.r], t);
        Self {
            c,
            pk: *public,
            ios: ios.to_vec(),
            zs,
            r: proof.r,
            s: proof.s,
        }
    }
}

/// Batch verifier for Thin VRF proofs.
pub struct BatchVerifier<S: ThinSuite> {
    items: Vec<BatchItem<S>>,
}

impl<S: ThinSuite> Default for BatchVerifier<S> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}

impl<S: ThinSuite> BatchVerifier<S> {
    /// Create a new empty batch verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a previously prepared item into the batch.
    pub fn push_prepared(&mut self, item: BatchItem<S>) {
        self.items.push(item);
    }

    /// Prepare and push a proof in one step.
    pub fn push(
        &mut self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        public: &Public<S>,
    ) {
        self.push_prepared(BatchItem::new(ios, ad, proof, public));
    }

    /// Verify all the proofs with one multi-scalar multiplication.
    ///
    /// Returns `Error::InvalidData` if a key or a point of an I/O pair is the
    /// identity, and `Error::VerificationFailure` if a proof is not valid.
    /// Subgroup membership is not checked (see [`PointWrapper`]).
    pub fn verify(&self) -> Result<(), Error> {
        use ark_ec::VariableBaseMSM;
        use ark_ff::Zero;

        let items = &self.items;
        if items.is_empty() {
            return Ok(());
        }
        // Checked here rather than in `BatchItem::new`, which cannot fail.
        if items
            .iter()
            .any(|item| utils::has_identity(item.pk.0, &item.ios))
        {
            return Err(Error::InvalidData);
        }

        // The weights depend on all the (c, s) pairs of the batch.
        let mut t = utils::batch_transcript::<S>(DomSep::ThinVrf);
        for e in items {
            t.absorb_serialize(&e.c);
            t.absorb_serialize(&e.s);
        }

        // Proof j, weighted by w_j:
        //   R_j + c_j * Y_j + sum_i(c_j * z_i * O_i) - s_j * G - sum_i(s_j * z_i * I_i) = 0
        // with z_0 = 1 for the Schnorr pair (G, Y_j). All proofs share the G base.
        let total_points: usize = items.iter().map(|e| 2 + 2 * e.ios.len()).sum::<usize>() + 1;
        let mut bases = Vec::with_capacity(total_points);
        let mut scalars = Vec::with_capacity(total_points);
        let mut g_scalar = ScalarField::<S>::zero();

        for item in items.iter() {
            // Random weights of SECURITY_PARAMETER bits for Schwartz-Zippel soundness.
            let w = weight_scalar::<S>(&mut t);

            let wc = w * item.c;
            let ws = w * item.s;

            bases.push(item.r);
            scalars.push(w);

            bases.push(item.pk.0);
            scalars.push(wc);

            g_scalar -= ws;

            for (i, io) in item.ios.iter().enumerate() {
                bases.push(io.output.0);
                scalars.push(wc * item.zs[i + 1]);

                bases.push(io.input.0);
                scalars.push(-(ws * item.zs[i + 1]));
            }
        }

        bases.push(S::GENERATOR);
        scalars.push(g_scalar);

        let result = <S::Affine as AffineRepr>::Group::msm_unchecked(&bases, &scalars);
        if !result.is_zero() {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::testing::{self as common, SuiteExt, TEST_SEED, random_val};

    pub fn prove_verify<S: ThinSuite>() {
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);

        let proof = secret.prove_thin(io, b"foo");
        let result = public.verify_thin(io, b"foo", &proof);
        assert!(result.is_ok());
    }

    pub fn batch_verify<S: ThinSuite>() {
        use thin::{BatchItem, BatchVerifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);

        let proof1 = secret.prove_thin(io, b"foo");
        let proof2 = secret.prove_thin(io, b"bar");

        assert!(public.verify_thin(io, b"foo", &proof1).is_ok());
        assert!(public.verify_thin(io, b"bar", &proof2).is_ok());

        let mut batch = BatchVerifier::new();
        batch.push(io, b"foo", &proof1, &public);
        batch.push(io, b"bar", &proof2, &public);
        assert!(batch.verify().is_ok());

        let mut batch = BatchVerifier::new();
        let entry1 = BatchItem::new(io, b"foo", &proof1, &public);
        let entry2 = BatchItem::new(io, b"bar", &proof2, &public);
        batch.push_prepared(entry1);
        batch.push_prepared(entry2);
        assert!(batch.verify().is_ok());

        let batch = BatchVerifier::<S>::new();
        assert!(batch.verify().is_ok());

        let mut batch = BatchVerifier::new();
        batch.push(io, b"foo", &proof1, &public);
        batch.push(io, b"wrong", &proof2, &public);
        assert!(batch.verify().is_err());
    }

    /// N=1 slice produces same proof as passing a single `VrfIo`.
    pub fn prove_verify_multi_single<S: ThinSuite>() {
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);

        let proof_single = secret.prove_thin(io, b"foo");
        let proof_slice = secret.prove_thin([io], b"foo");

        let encode = |p: &thin::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));
        assert!(public.verify_thin(io, b"foo", &proof_slice).is_ok());
        assert!(public.verify_thin([io], b"foo", &proof_single).is_ok());
    }

    /// With `Y = 0` the equation is `s * G == R`, which anybody can satisfy. Both
    /// verifiers must reject it also for a key that skipped the checked decoder.
    pub fn identity_public_key_rejected<S: ThinSuite>() {
        use thin::BatchVerifier;

        let identity = Public::<S>::from_affine_unchecked(AffinePoint::<S>::zero());
        let s = ScalarField::<S>::from(0x5eed_u64);
        let forged = Proof::<S> {
            r: (S::GENERATOR * s).into_affine(),
            s,
        };

        assert!(identity.verify_thin([], b"forgery", &forged).is_err());

        let mut batch = BatchVerifier::new();
        batch.push([], b"forgery", &forged, &identity);
        assert!(batch.verify().is_err());
    }

    /// An off-curve key or input, such as `(0, 0)` on a twisted Edwards curve,
    /// gives `s * I_m - c * O_m = (0, 0, 0, 0)`, which arkworks finds equal to
    /// every point. Verify must reject it, as the batch verifier does.
    pub fn off_curve_point_rejected<S: ThinSuite>() {
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let io = secret.vrf_io(Input::new(b"foo").unwrap());
        let proof = secret.prove_thin(io, b"bar");
        let off_curve = common::off_curve_point::<S>();

        let public = Public::<S>::from_affine_unchecked(off_curve);
        assert!(public.verify_thin(io, b"bar", &proof).is_err());

        let input = Input::from_affine_unchecked(off_curve);
        let io = VrfIo { input, ..io };
        assert!(secret.public().verify_thin(io, b"bar", &proof).is_err());
    }

    /// `(0, 0)` satisfies `O = x * I` for every key, so it binds its output to no
    /// signer. The second case hides it behind a valid pair, where the merged
    /// pair does not show it.
    pub fn identity_io_pair_rejected<S: ThinSuite>() {
        use thin::BatchVerifier;

        let identity_io = VrfIo::<S> {
            input: Input::from_affine_unchecked(AffinePoint::<S>::zero()),
            output: Output::from_affine_unchecked(AffinePoint::<S>::zero()),
        };

        for seed in [common::TEST_SEED, [0x11; 32]] {
            let secret = Secret::<S>::from_seed(seed);
            let public = secret.public();

            let proof = secret.prove_thin([identity_io], b"forgery");
            assert!(
                public
                    .verify_thin([identity_io], b"forgery", &proof)
                    .is_err()
            );

            let mut batch = BatchVerifier::new();
            batch.push([identity_io], b"forgery", &proof, &public);
            assert!(batch.verify().is_err());

            let good_io = secret.vrf_io(Input::new(b"good").unwrap());
            let ios = [good_io, identity_io];
            let proof = secret.prove_thin(ios, b"forgery");
            assert!(public.verify_thin(ios, b"forgery", &proof).is_err());

            let mut batch = BatchVerifier::new();
            batch.push(ios, b"forgery", &proof, &public);
            assert!(batch.verify().is_err());
        }
    }

    /// N=3 VRF pairs: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: ThinSuite>() {
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let ios: Vec<VrfIo<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                secret.vrf_io(input)
            })
            .collect();

        let proof = secret.prove_thin(&ios[..], b"bar");
        assert!(public.verify_thin(&ios[..], b"bar", &proof).is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(public.verify_thin(&bad_ios[..], b"bar", &proof).is_err());

        let mut bad_ios = ios.clone();
        bad_ios[0].input = ios[1].input;
        assert!(public.verify_thin(&bad_ios[..], b"bar", &proof).is_err());

        assert!(public.verify_thin(&ios[..], b"baz", &proof).is_err());
    }

    /// With no VRF pairs, the proof is a Schnorr signature over `ad`.
    pub fn prove_verify_multi_empty<S: ThinSuite>() {
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let proof = secret.prove_thin([], b"bar");
        assert!(public.verify_thin([], b"bar", &proof).is_ok());

        assert!(public.verify_thin([], b"baz", &proof).is_err());
    }

    /// One proof must have one encoding. `R` is the identity only for a zero
    /// nonce, so that proof is built by hand.
    pub fn proof_encoding_is_canonical<S: ThinSuite>() {
        use ark_serialize::Compress;

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);
        let proof = secret.prove_thin(io, b"foo");

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(public.verify_thin(io, b"foo", &decoded).is_ok());
        let mut reencoded = Vec::new();
        decoded.serialize_compressed(&mut reencoded).unwrap();
        assert_eq!(bytes, reencoded);

        let identity_r = Proof::<S> {
            r: AffinePoint::<S>::zero(),
            s: proof.s,
        };
        let mut bytes = Vec::new();
        identity_r.serialize_compressed(&mut bytes).unwrap();
        let r_range = 0..identity_r.r.compressed_size();
        let aliases = common::assert_aliases_rejected::<AffinePoint<S>>(
            &bytes,
            r_range,
            Compress::Yes,
            |bytes| {
                Proof::<S>::deserialize_compressed(bytes).is_ok()
                    || common::decodes_inside_vec::<Proof<S>>(bytes, Compress::Yes)
            },
        );
        assert!(!aliases.is_empty());
    }

    /// Runs the MSM branch of `merge_ios` (`MSM_THRESHOLD` pairs). The batch
    /// verifier does not merge, so it checks the merge of the prover.
    pub fn prove_verify_multi_msm<S: ThinSuite>() {
        use crate::utils::common::MSM_THRESHOLD;
        use thin::BatchVerifier;

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let ios: Vec<VrfIo<S>> = (0..MSM_THRESHOLD as u8)
            .map(|i| secret.vrf_io(Input::new(&[i]).unwrap()))
            .collect();

        let proof = secret.prove_thin(&ios[..], b"msm");
        assert!(public.verify_thin(&ios[..], b"msm", &proof).is_ok());
        let mut batch = BatchVerifier::new();
        batch.push(&ios[..], b"msm", &proof, &public);
        assert!(batch.verify().is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[MSM_THRESHOLD - 1].output = ios[0].output;
        assert!(public.verify_thin(&bad_ios[..], b"msm", &proof).is_err());
        let mut batch = BatchVerifier::new();
        batch.push(&bad_ios[..], b"msm", &proof, &public);
        assert!(batch.verify().is_err());
    }

    #[macro_export]
    macro_rules! thin_suite_tests {
        ($suite:ty) => {
            mod thin {
                use super::*;

                #[test]
                fn proof_encoding_is_canonical() {
                    $crate::thin::testing::proof_encoding_is_canonical::<$suite>()
                }

                #[test]
                fn prove_verify() {
                    $crate::thin::testing::prove_verify::<$suite>();
                }

                #[test]
                fn prove_verify_multi_single() {
                    $crate::thin::testing::prove_verify_multi_single::<$suite>();
                }

                #[test]
                fn prove_verify_multi() {
                    $crate::thin::testing::prove_verify_multi::<$suite>();
                }

                #[test]
                fn prove_verify_multi_empty() {
                    $crate::thin::testing::prove_verify_multi_empty::<$suite>();
                }

                #[test]
                fn prove_verify_multi_msm() {
                    $crate::thin::testing::prove_verify_multi_msm::<$suite>();
                }

                #[test]
                fn batch_verify() {
                    $crate::thin::testing::batch_verify::<$suite>();
                }

                #[test]
                fn identity_public_key_rejected() {
                    $crate::thin::testing::identity_public_key_rejected::<$suite>();
                }

                #[test]
                fn identity_io_pair_rejected() {
                    $crate::thin::testing::identity_io_pair_rejected::<$suite>();
                }

                #[test]
                fn off_curve_point_rejected() {
                    $crate::thin::testing::off_curve_point_rejected::<$suite>();
                }

                $crate::test_vectors!($crate::thin::testing::TestVector<$suite>);
            }
        };
    }

    pub struct TestVector<S: ThinSuite> {
        pub base: common::TestVector<S>,
        pub proof_r: AffinePoint<S>,
        pub proof_s: ScalarField<S>,
    }

    impl<S: ThinSuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let r = hex::encode(common::point_encode::<S>(&self.proof_r));
            let s = hex::encode(common::scalar_encode::<S>(&self.proof_s));
            f.debug_struct("TestVector")
                .field("base", &self.base)
                .field("proof_r", &r)
                .field("proof_s", &s)
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: ThinSuite + SuiteExt + std::fmt::Debug,
    {
        fn name() -> String {
            S::SUITE_NAME.to_string() + "_thin"
        }

        fn new(comment: &str, seed: &[u8; 32], alpha: &[u8], ad: &[u8]) -> Self {
            let base = common::TestVector::new(comment, seed, alpha, ad);
            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(base.h),
                output: Output::from_affine_unchecked(base.gamma),
            };
            let secret = Secret::from_scalar(base.sk);
            let proof: Proof<S> = secret.prove_thin(io, ad);
            Self {
                base,
                proof_r: proof.r,
                proof_s: proof.s,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let proof_r = common::point_decode::<S>(&map.get_bytes("proof_r")).unwrap();
            let proof_s = common::scalar_decode::<S>(&map.get_bytes("proof_s"));
            Self {
                base,
                proof_r,
                proof_s,
            }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let items = [
                (
                    "proof_r",
                    hex::encode(common::point_encode::<S>(&self.proof_r)),
                ),
                (
                    "proof_s",
                    hex::encode(common::scalar_encode::<S>(&self.proof_s)),
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
            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(self.base.h),
                output: Output::from_affine_unchecked(self.base.gamma),
            };
            let sk = Secret::from_scalar(self.base.sk);
            let proof = sk.prove_thin(io, &self.base.ad);
            assert_eq!(self.proof_r, proof.r, "Thin VRF proof R mismatch");
            assert_eq!(self.proof_s, proof.s, "Thin VRF proof s mismatch");

            let pk = Public::<S>::from_affine_unchecked(self.base.pk);
            assert!(pk.verify_thin(io, &self.base.ad, &proof).is_ok());
        }
    }

    /// A prover who knows `d` with `I = d * G` can prove any output for `I`, so
    /// `Input` comes only from hash-to-curve.
    #[test]
    fn known_dlog_input_forgery() {
        use ark_ff::Field;

        type S = crate::suites::testing::TestSuite;
        type Sc = ScalarField<S>;

        let g = S::GENERATOR;

        let sk = Sc::from(42);
        let pk = (g * sk).into_affine();

        let d = Sc::from(7);
        let input_pt = (g * d).into_affine();
        let input = Input::<S>::from_affine_unchecked(input_pt);

        let honest_output = (input_pt * sk).into_affine();

        let t_scalar = Sc::from(1234);
        let fake_output_pt = (g * t_scalar).into_affine();
        assert_ne!(fake_output_pt, honest_output);
        let fake_output = Output::<S>::from_affine_unchecked(fake_output_pt);

        let ad: &[u8] = b"attack";
        let fake_io = VrfIo {
            input,
            output: fake_output,
        };

        let fake_ios: &[VrfIo<S>] = &[fake_io];
        let (transcript, zs) = vrf_transcript_scalars::<S>(pk, fake_ios, ad);
        let (z0, z1) = (zs[0], zs[1]);

        let merged_input = (g * z0 + input_pt * z1).into_affine();

        // I_m and O_m are multiples of G, so the prover knows the DLEQ secret.
        let x = (z0 * sk + z1 * t_scalar) * (z0 + z1 * d).inverse().unwrap();

        let k = Sc::from(9999);
        let r = (merged_input * k).into_affine();
        let c = S::challenge(&[&r], transcript);
        let s = k + c * x;

        let forged_proof = Proof::<S> { r, s };

        let public = Public::<S>::from_affine_unchecked(pk);
        assert!(
            public.verify_thin(fake_io, ad, &forged_proof).is_ok(),
            "Forged proof must verify when input discrete log is known"
        );
    }
}
