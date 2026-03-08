//! # Thin-VRF
//!
//! Based on the PedVRF construction from Section 4 of
//! [BCHSV23](https://eprint.iacr.org/2023/002), reduced to EC-VRF form
//! by setting the blinding factor `b = 0` and using `pk = sk*G` directly
//! (see remark on page 13 of the paper).
//!
//! ThinVrf merges the public-key Schnorr pair `(G, P)` and the VRF I/O pair
//! `(I, O)` into a single DLEQ relation via delinearization, then proves it
//! with a Schnorr-like proof `(R, s)`. The `(R, s)` format (storing nonce
//! commitment rather than challenge) enables batch verification.
//!
//! # Security
//!
//! The input point `I` **must** be constructed via hash-to-curve (e.g.
//! [`Input::new`]) so that nobody knows its discrete-log relation to the
//! generator `G`. If the prover knew such a relation, they could forge
//! outputs. This is critical because the delinearization merges the Schnorr
//! and VRF pairs into a single check.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::thin::{Prover, Verifier};
//!
//! let secret = Secret::from_seed(b"seed");
//! let public = secret.public();
//! let input = Input::new(b"example input").unwrap();
//! let io = secret.vrf_io(input);
//!
//! // Proving
//! let proof = secret.prove(io, b"aux data");
//!
//! // Verification
//! let result = public.verify(io, b"aux data", &proof);
//! ```

use crate::{utils::challenge_scalar, *};

/// Marker trait for suites that support the Thin VRF scheme.
///
/// Blanket-implemented for all types implementing [`Suite`].
pub trait ThinVrfSuite: Suite {}

impl<T> ThinVrfSuite for T where T: Suite {}

/// Thin VRF proof.
///
/// Schnorr-like proof over the delinearized merged DLEQ relation:
/// - `r`: Nonce commitment R = k * I_m
/// - `s`: Response scalar s = k + c * sk
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: ThinVrfSuite> {
    /// Nonce commitment on the merged input.
    pub r: AffinePoint<S>,
    /// Response scalar.
    pub s: ScalarField<S>,
}

fn chain_ios<'a, S: ThinVrfSuite>(
    public: AffinePoint<S>,
    ios: &'a [VrfIo<S>],
) -> impl ExactSizeIterator<Item = VrfIo<S>> + Clone + 'a {
    let schnorr = core::iter::once(VrfIo {
        input: Input(S::generator()),
        output: Output(public),
    });
    utils::common::ExactChain::new(ios.iter().copied(), schnorr)
}

/// Build a Thin-VRF transcript from public key, VRF I/O pairs, and additional data.
///
/// Absorbs the raw I/O pairs (Schnorr pair + VRF pairs) into the transcript,
/// delinearizes them into a single merged pair via [`merge_ios`], then absorbs
/// additional data. Returns the transcript and the merged `VrfIo`.
#[inline(always)]
fn vrf_transcript<S: ThinVrfSuite>(
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    utils::vrf_transcript_from_iter(chain_ios(public, ios.as_ref()), ad)
}

/// Build a Thin-VRF transcript returning raw delinearization scalars.
///
/// Used by batch verification, which needs the individual points and z scalars
/// to build an expanded MSM without computing the merged pair.
#[inline(always)]
fn vrf_transcript_scalars<S: ThinVrfSuite>(
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    utils::vrf_transcript_scalars_from_iter(chain_ios(public, ios.as_ref()), ad)
}

/// Trait for types that can generate Thin VRF proofs.
pub trait Prover<S: ThinVrfSuite> {
    /// Generate a proof for the given VRF I/O pairs and additional data.
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for entities that can verify Thin VRF proofs.
pub trait Verifier<S: ThinVrfSuite> {
    /// Verify a proof for the given VRF I/O pairs and additional data.
    fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: ThinVrfSuite> Prover<S> for Secret<S> {
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let (t, merged) = vrf_transcript::<S>(self.public.0, ios, ad);

        // Nonce
        let k = S::nonce(&self.scalar, Some(t.clone()));

        // R = k * I_m (secret nonce on merged input)
        let r = smul!(merged.input.0, k).into_affine();

        // Challenge
        let c = S::challenge(&[&r], Some(t));

        // Response
        let s = k + c * self.scalar;

        Proof { r, s }
    }
}

impl<S: ThinVrfSuite> Verifier<S> for Public<S> {
    fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof { r, s } = proof;
        let (t, merged) = vrf_transcript::<S>(self.0, ios, ad);

        // Challenge
        let c = S::challenge(&[r], Some(t));

        // Verification: s * I_m == R + c * O_m
        let lhs = smul!(merged.input.0, *s);
        let rhs = r.into_group() + smul!(merged.output.0, c);
        if lhs != rhs {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

/// Deferred Thin VRF verification data for batch verification.
///
/// Stores raw points and delinearization scalars instead of the merged pair,
/// so that `prepare` requires no EC ops (just hashing). The expanded
/// verification equation uses these directly in the batch MSM.
pub struct BatchItem<S: ThinVrfSuite> {
    c: ScalarField<S>,
    pk: AffinePoint<S>,
    ios: Vec<VrfIo<S>>,
    zs: Vec<ScalarField<S>>,
    r: AffinePoint<S>,
    s: ScalarField<S>,
}

/// Batch verifier for Thin VRF proofs.
///
/// Collects multiple proofs and verifies them together via a single
/// multi-scalar multiplication.
pub struct BatchVerifier<S: ThinVrfSuite> {
    items: Vec<BatchItem<S>>,
}

impl<S: ThinVrfSuite> Default for BatchVerifier<S> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}

impl<S: ThinVrfSuite> BatchVerifier<S> {
    /// Create a new empty batch verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepare a proof for batch verification.
    ///
    /// Computes delinearization scalars and challenge via hashing only (no EC
    /// ops). Stores the raw points and z scalars for the expanded verification
    /// equation in [`Self::verify`].
    pub fn prepare(
        public: &Public<S>,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> BatchItem<S> {
        let ios = ios.as_ref();
        let (t, zs) = vrf_transcript_scalars::<S>(public.0, ios, ad);
        let c = S::challenge(&[&proof.r], Some(t));
        BatchItem {
            c,
            pk: public.0,
            ios: ios.to_vec(),
            zs,
            r: proof.r,
            s: proof.s,
        }
    }

    /// Push a previously prepared entry into the batch.
    pub fn push_prepared(&mut self, entry: BatchItem<S>) {
        self.items.push(entry);
    }

    /// Prepare and push a proof in one step.
    pub fn push(
        &mut self,
        public: &Public<S>,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) {
        let entry = Self::prepare(public, ios, ad, proof);
        self.push_prepared(entry);
    }

    /// Batch-verify all collected proofs using a single multi-scalar multiplication.
    ///
    /// For each proof j, the expanded verification equation is:
    ///   R_j + c_j*z0_j*pk_j + sum_i(c_j*z_ij*O_ij) - s_j*z0_j*G - sum_i(s_j*z_ij*I_ij) == 0
    ///
    /// With random weights w_j, G is accumulated as a shared base, yielding a
    /// `(sum_j(2 + 2*M_j) + 1)`-point MSM (where M_j is the number of VRF
    /// pairs in proof j).
    ///
    /// Returns `Ok(())` if all proofs verify, `Err(VerificationFailure)` otherwise.
    pub fn verify(&self) -> Result<(), Error> {
        use ark_ec::VariableBaseMSM;
        use ark_ff::Zero;

        let items = &self.items;
        if items.is_empty() {
            return Ok(());
        }

        // Deterministic random scalars derived from all (c, s) pairs.
        let mut t = S::Transcript::new(S::SUITE_ID);
        t.absorb_raw(b"thin-batch");
        for e in items {
            t.absorb_serialize(&e.c);
            t.absorb_serialize(&e.s);
        }

        // Build MSM with expanded equation: per-proof (2+2M) points + 1 shared G.
        let total_points: usize = items.iter().map(|e| 2 + 2 * e.ios.len()).sum::<usize>() + 1;
        let mut bases = Vec::with_capacity(total_points);
        let mut scalars = Vec::with_capacity(total_points);
        let mut g_scalar = ScalarField::<S>::zero();

        for item in items.iter() {
            // 128-bit random weights for Schwartz-Zippel soundness.
            let w = challenge_scalar::<S>(&mut t);

            let wc = w * item.c;
            let ws = w * item.s;

            // R_j with scalar w_j
            bases.push(item.r);
            scalars.push(w);

            // pk_j with scalar w_j*c_j*z0_j
            bases.push(item.pk);
            scalars.push(wc * item.zs[0]);

            // Accumulate G scalar: -w_j*s_j*z0_j
            g_scalar -= ws * item.zs[0];

            // Per VRF pair: O_i with w*c*z_i, I_i with -w*s*z_i
            for (i, io) in item.ios.iter().enumerate() {
                bases.push(io.output.0);
                scalars.push(wc * item.zs[i + 1]);

                bases.push(io.input.0);
                scalars.push(-(ws * item.zs[i + 1]));
            }
        }

        // Shared generator base.
        bases.push(S::generator());
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
    use crate::testing::{self as common, random_val, SuiteExt, TEST_SEED};

    pub fn prove_verify<S: ThinVrfSuite>() {
        use thin::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(random_val(None));
        let io = secret.vrf_io(input);

        let proof = secret.prove(io, b"foo");
        let result = public.verify(io, b"foo", &proof);
        assert!(result.is_ok());
    }

    pub fn batch_verify<S: ThinVrfSuite>() {
        use thin::{BatchVerifier, Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(random_val(None));
        let io = secret.vrf_io(input);

        let proof1 = secret.prove(io, b"foo");
        let proof2 = secret.prove(io, b"bar");

        // Single-proof verification still works.
        assert!(public.verify(io, b"foo", &proof1).is_ok());
        assert!(public.verify(io, b"bar", &proof2).is_ok());

        // Batch using push.
        let mut batch = BatchVerifier::new();
        batch.push(&public, io, b"foo", &proof1);
        batch.push(&public, io, b"bar", &proof2);
        assert!(batch.verify().is_ok());

        // Batch using prepare + push_prepared.
        let mut batch = BatchVerifier::new();
        let entry1 = BatchVerifier::prepare(&public, io, b"foo", &proof1);
        let entry2 = BatchVerifier::prepare(&public, io, b"bar", &proof2);
        batch.push_prepared(entry1);
        batch.push_prepared(entry2);
        assert!(batch.verify().is_ok());

        // Empty batch is ok.
        let batch = BatchVerifier::<S>::new();
        assert!(batch.verify().is_ok());

        // Bad additional data should fail.
        let mut batch = BatchVerifier::new();
        batch.push(&public, io, b"foo", &proof1);
        batch.push(&public, io, b"wrong", &proof2);
        assert!(batch.verify().is_err());
    }

    /// N=1 slice produces same proof as passing a single `VrfIo`.
    pub fn prove_verify_multi_single<S: ThinVrfSuite>() {
        use thin::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(random_val(None));
        let io = secret.vrf_io(input);

        let proof_single = secret.prove(io, b"foo");
        let proof_slice = secret.prove([io], b"foo");

        // Byte-identical proofs
        let encode = |p: &thin::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));

        // Cross-verification
        assert!(public.verify(io, b"foo", &proof_slice).is_ok());
        assert!(public.verify([io], b"foo", &proof_single).is_ok());
    }

    /// N=3 VRF pairs: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: ThinVrfSuite>() {
        use thin::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let ios: Vec<VrfIo<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                secret.vrf_io(input)
            })
            .collect();

        let proof = secret.prove(&ios[..], b"bar");
        assert!(public.verify(&ios[..], b"bar", &proof).is_ok());

        // Tamper: wrong output on ios[1]
        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(public.verify(&bad_ios[..], b"bar", &proof).is_err());

        // Tamper: wrong input on ios[0]
        let mut bad_ios = ios.clone();
        bad_ios[0].input = ios[1].input;
        assert!(public.verify(&bad_ios[..], b"bar", &proof).is_err());

        // Tamper: wrong ad
        assert!(public.verify(&ios[..], b"baz", &proof).is_err());
    }

    /// N=0 VRF pairs degenerates to Schnorr signature over ad.
    pub fn prove_verify_multi_empty<S: ThinVrfSuite>() {
        use thin::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let proof = secret.prove([], b"bar");
        assert!(public.verify([], b"bar", &proof).is_ok());

        // Wrong ad should fail
        assert!(public.verify([], b"baz", &proof).is_err());
    }

    #[macro_export]
    macro_rules! thin_suite_tests {
        ($suite:ty) => {
            mod thin {
                use super::*;

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
                fn batch_verify() {
                    $crate::thin::testing::batch_verify::<$suite>();
                }

                $crate::test_vectors!($crate::thin::testing::TestVector<$suite>);
            }
        };
    }

    pub struct TestVector<S: ThinVrfSuite> {
        pub base: common::TestVector<S>,
        pub proof_r: AffinePoint<S>,
        pub proof_s: ScalarField<S>,
    }

    impl<S: ThinVrfSuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let r = hex::encode(codec::point_encode::<S>(&self.proof_r));
            let s = hex::encode(codec::scalar_encode::<S>(&self.proof_s));
            f.debug_struct("TestVector")
                .field("base", &self.base)
                .field("proof_r", &r)
                .field("proof_s", &s)
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: ThinVrfSuite + SuiteExt + std::fmt::Debug,
    {
        fn name() -> String {
            S::suite_name() + "_thin"
        }

        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, salt, ad);
            let io = VrfIo {
                input: Input::<S>::from_affine(base.h),
                output: Output::from_affine(base.gamma),
            };
            let secret = Secret::from_scalar(base.sk);
            let proof: Proof<S> = secret.prove(io, ad);
            Self {
                base,
                proof_r: proof.r,
                proof_s: proof.s,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let proof_r = codec::point_decode::<S>(&map.get_bytes("proof_r")).unwrap();
            let proof_s = codec::scalar_decode::<S>(&map.get_bytes("proof_s"));
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
                    hex::encode(codec::point_encode::<S>(&self.proof_r)),
                ),
                (
                    "proof_s",
                    hex::encode(codec::scalar_encode::<S>(&self.proof_s)),
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
                input: Input::<S>::from_affine(self.base.h),
                output: Output::from_affine(self.base.gamma),
            };
            let sk = Secret::from_scalar(self.base.sk);
            let proof = sk.prove(io, &self.base.ad);
            assert_eq!(self.proof_r, proof.r, "Thin VRF proof R mismatch");
            assert_eq!(self.proof_s, proof.s, "Thin VRF proof s mismatch");

            let pk = Public(self.base.pk);
            assert!(pk.verify(io, &self.base.ad, &proof).is_ok());
        }
    }

    /// Demonstrates that a malicious prover who knows the discrete-log relation
    /// between the VRF input `I` and the generator `G` (i.e. knows `d` s.t.
    /// `I = d * G`) can forge a valid Thin-VRF proof for an arbitrary output.
    ///
    /// This is why `Input` **must** be constructed via hash-to-curve.
    #[test]
    fn known_dlog_input_forgery() {
        use ark_ff::Field;

        type S = crate::suites::testing::TestSuite;
        type Sc = ScalarField<S>;

        let g = S::generator();

        // Attacker's key pair.
        let sk = Sc::from(42);
        let pk = (g * sk).into_affine();

        // Input with KNOWN discrete log: I = d * G.
        let d = Sc::from(7);
        let input_pt = (g * d).into_affine();
        let input = Input::<S>::from_affine(input_pt);

        // Honest output would be O = sk * I.
        let honest_output = (input_pt * sk).into_affine();

        // Attacker picks a DIFFERENT output: O' = t * G, with t != sk * d.
        let t_scalar = Sc::from(1234);
        let fake_output_pt = (g * t_scalar).into_affine();
        assert_ne!(fake_output_pt, honest_output);
        let fake_output = Output::<S>::from_affine(fake_output_pt);

        let ad: &[u8] = b"attack";
        let fake_io = VrfIo {
            input,
            output: fake_output,
        };

        // Replicate what prove/verify do.
        let fake_ios: &[VrfIo<S>] = &[fake_io];
        let (transcript, zs) = vrf_transcript_scalars::<S>(pk, fake_ios, ad);
        let (z0, z1) = (zs[0], zs[1]);

        // Compute merged input I_m = z0*G + z1*I for the forgery.
        let merged_input = (g * z0 + input_pt * z1).into_affine();

        // --- Forge the proof ---
        //
        // Because I = d*G, the merged input is I_m = (z0 + z1*d) * G and the
        // merged output is O_m = (z0*sk + z1*t) * G, both multiples of G.
        // The effective DLEQ secret is x = (z0*sk + z1*t) / (z0 + z1*d).
        let x = (z0 * sk + z1 * t_scalar) * (z0 + z1 * d).inverse().unwrap();

        // Standard Schnorr proof with the derived secret.
        let k = Sc::from(9999);
        let r = (merged_input * k).into_affine();
        let c = S::challenge(&[&r], Some(transcript));
        let s = k + c * x;

        let forged_proof = Proof::<S> { r, s };

        // The forged proof verifies despite O' != sk * I.
        //
        // The verifier checks: s * I_m == R + c * O_m
        //
        // Expanding with I = d*G (everything collapses to multiples of G):
        //   I_m = z0*G + z1*I = (z0 + z1*d) * G
        //   O_m = z0*pk + z1*O' = (z0*sk + z1*t) * G
        //
        // LHS: s * I_m = (k + c*x) * (z0 + z1*d) * G
        // RHS: R + c * O_m = k*(z0 + z1*d)*G + c*(z0*sk + z1*t)*G
        //
        // Since x = (z0*sk + z1*t) / (z0 + z1*d):
        //   LHS = (k + c*x) * (z0 + z1*d) * G
        //       = k*(z0 + z1*d)*G + c * [(z0*sk + z1*t) / (z0 + z1*d)] * (z0 + z1*d) * G
        //       = k*(z0 + z1*d)*G + c*(z0*sk + z1*t)*G
        //       = RHS
        let public = Public::<S>(pk);
        assert!(
            public.verify(fake_io, ad, &forged_proof).is_ok(),
            "Forged proof must verify when input discrete log is known"
        );
    }
}
