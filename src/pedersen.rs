//! # Pedersen VRF
//!
//! Key-hiding VRF based on the PedVRF construction from Section 4 of
//! [BCHSV23](https://eprint.iacr.org/2023/002). Replaces the public key with a
//! Pedersen commitment to the secret key, allowing verification without revealing
//! which specific public key was used. Serves as a building block for anonymized
//! ring signatures.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::pedersen::{Prover, Verifier};
//!
//! let secret = Secret::from_seed([0; 32]);
//! let public = secret.public();
//! let input = Input::new(b"example input").unwrap();
//! let io = secret.vrf_io(input);
//!
//! // Proving
//! let (proof, blinding) = secret.prove(io, b"aux data");
//!
//! // Verification
//! let result = Public::verify(io, b"aux data", &proof);
//!
//! // Unblinding: verify the proof was created using a specific public key
//! let expected = (public.0 + BandersnatchSha512Ell2::BLINDING_BASE * blinding).into_affine();
//! assert_eq!(proof.key_commitment(), expected);
//! ```

use crate::Suite;
use crate::utils;
use crate::utils::common::DomSep;
use crate::utils::straus::short_msm;
use crate::*;
use ark_ec::VariableBaseMSM;

/// Seed hashed to curve to produce [`PedersenSuite::BLINDING_BASE`] in built-in suites.
pub const PEDERSEN_BLINDING_BASE_SEED: &[u8] = b"pedersen-blinding";

/// Suite extension for Pedersen VRF support.
///
/// Provides the additional cryptographic parameters required by the Pedersen VRF scheme.
pub trait PedersenSuite: Suite {
    /// Blinding base.
    const BLINDING_BASE: AffinePoint<Self>;

    /// Pedersen blinding factor.
    ///
    /// Default implementation is deterministic. All parameters but `secret` are public.
    fn blinding(secret: &ScalarField<Self>, mut transcript: Self::Transcript) -> ScalarField<Self> {
        transcript.absorb_raw(&[DomSep::PedersenBlinding as u8]);
        Self::nonce(secret, Some(transcript))
    }
}

/// Pedersen VRF proof.
///
/// Zero-knowledge proof with key-hiding properties:
/// - `pk_com`: Commitment to the public key (Y_b = x·G + b·B)
/// - `r`: Nonce commitment for the generator (R = k·G + k_b·B)
/// - `ok`: Nonce commitment for the input point (O_k = k·I)
/// - `s`: Response scalar for the secret key
/// - `sb`: Response scalar for the blinding factor
///
/// Deserialization via [`CanonicalDeserialize`] includes subgroup checks for
/// curve points, so deserialized proofs are guaranteed to contain valid points.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: PedersenSuite> {
    pk_com: AffinePoint<S>,
    r: AffinePoint<S>,
    ok: AffinePoint<S>,
    s: ScalarField<S>,
    sb: ScalarField<S>,
}

impl<S: PedersenSuite> Proof<S> {
    /// Get public key commitment from proof.
    pub fn key_commitment(&self) -> AffinePoint<S> {
        self.pk_com
    }
}

/// Trait for types that can generate Pedersen VRF proofs.
pub trait Prover<S: PedersenSuite> {
    /// Generate a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before proving.
    ///
    /// Returns the proof together with the associated blinding factor.
    fn prove(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>);
}

/// Trait for entities that can verify Pedersen VRF proofs.
///
/// Verifies that a VRF output is correctly derived from an input using a
/// committed public key, without revealing which specific public key was used.
///
/// All curve points involved in verification (I/O pairs and proof points)
/// are assumed to be in the prime-order subgroup. This is guaranteed when
/// points are constructed through checked constructors ([`Input::from_affine`],
/// [`Output::from_affine`]) or through trusted operations like [`Input::new`]
/// (hash-to-curve) and [`Secret::vrf_io`]. Proof points are guaranteed valid
/// when deserialized via [`CanonicalDeserialize`] (which includes subgroup
/// checks) or produced by [`Prover::prove`].
///
/// Using unchecked constructors (e.g. [`Input::from_affine_unchecked`]) places
/// the burden of subgroup validation on the caller. Passing points with
/// cofactor components leads to undefined verification behavior.
pub trait Verifier<S: PedersenSuite> {
    /// Verify a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before verifying.
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::VerificationFailure)` otherwise.
    fn verify(
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: PedersenSuite> Prover<S> for Secret<S> {
    fn prove(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>) {
        let (mut t, io) = utils::vrf_transcript::<S>(DomSep::PedersenVrf, ios, ad);

        // Build blinding factor from T.fork()
        let blinding = S::blinding(&self.scalar, t.clone());

        // Yb = x*G + b*B = PK + b*B
        let bb = smul!(S::BLINDING_BASE, blinding);
        let pk_com = (self.public.0.into_group() + bb).into_affine();

        // Absorb Yb into the transcript
        t.absorb_serialize(&pk_com);

        // Nonces from T.fork()
        let k = S::nonce(&self.scalar, Some(t.clone()));
        let kb = S::nonce(&blinding, Some(t.clone()));

        // R = k*G + kb*B
        let kg = smul!(S::generator(), k);
        let kbb = smul!(S::BLINDING_BASE, kb);
        let r = kg + kbb;

        // Ok = k*I
        let ok = smul!(io.input.0, k);

        let norms = CurveGroup::normalize_batch(&[r, ok]);
        let (r, ok) = (norms[0], norms[1]);

        // c = challenge([R, Ok], T)
        let c = S::challenge(&[&r, &ok], Some(t));

        // s = k + c*x
        let s = k + c * self.scalar;
        // sb = kb + c*b
        let sb = kb + c * blinding;

        let proof = Proof {
            pk_com,
            r,
            ok,
            s,
            sb,
        };
        (proof, blinding)
    }
}

impl<S: PedersenSuite> Verifier<S> for Public<S> {
    fn verify(
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof {
            pk_com,
            r,
            ok,
            s,
            sb,
        } = proof;

        let (mut t, io) = utils::vrf_transcript::<S>(DomSep::PedersenVrf, ios, ad);

        // Absorb Yb into the transcript
        t.absorb_serialize(pk_com);

        // c = challenge([R, Ok], T)
        let c = S::challenge(&[r, ok], Some(t));

        let neg_c = -c;

        // Eq1: s*I - c*O == Ok
        // Verifies that the VRF output O is correctly derived from the input I
        // using the same secret scalar x committed in the proof. Expanding the
        // response s = k + c*x gives s*I = k*I + c*x*I = Ok + c*O.
        let lhs1 = short_msm(&[io.input.0, io.output.0], &[*s, neg_c], 2);
        if lhs1 != ok.into_group() {
            return Err(Error::VerificationFailure);
        }

        // Eq2: s*G + sb*B - c*Yb == R
        // Verifies knowledge of both the secret key x and blinding factor b
        // committed in the public key commitment Yb = x*G + b*B. Expanding
        // s = k + c*x and sb = kb + c*b gives s*G + sb*B = R + c*Yb.
        let lhs2 = short_msm(
            &[S::generator(), S::BLINDING_BASE, *pk_com],
            &[*s, *sb, neg_c],
            1,
        );
        if lhs2 != r.into_group() {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

/// Deferred Pedersen verification data for batch verification.
///
/// Captures all the information needed to verify a single Pedersen proof,
/// allowing multiple proofs to be verified together via a single MSM.
pub struct BatchItem<S: PedersenSuite> {
    c: ScalarField<S>,
    input: AffinePoint<S>,
    output: AffinePoint<S>,
    pk_com: AffinePoint<S>,
    r: AffinePoint<S>,
    ok: AffinePoint<S>,
    s: ScalarField<S>,
    sb: ScalarField<S>,
}

/// Batch verifier for Pedersen VRF proofs.
///
/// Collects multiple proofs and verifies them together via a single
/// multi-scalar multiplication.
///
/// The same subgroup membership assumptions as [`Verifier`] apply to all
/// points fed into the batch (I/O pairs and proof points).
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

    /// Prepare a proof for batch verification.
    ///
    /// Computes the challenge and packages all data needed for deferred
    /// verification. This is cheap (one hash, no scalar multiplications)
    /// and can be done in parallel.
    pub fn prepare(
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> BatchItem<S> {
        let (mut t, io) = utils::vrf_transcript::<S>(DomSep::PedersenVrf, ios, ad);
        t.absorb_serialize(&proof.pk_com);
        let c = S::challenge(&[&proof.r, &proof.ok], Some(t));
        BatchItem {
            c,
            input: io.input.0,
            output: io.output.0,
            pk_com: proof.pk_com,
            r: proof.r,
            ok: proof.ok,
            s: proof.s,
            sb: proof.sb,
        }
    }

    /// Push a previously prepared entry into the batch.
    pub fn push_prepared(&mut self, entry: BatchItem<S>) {
        self.items.push(entry);
    }

    /// Prepare and push a proof in one step.
    pub fn push(&mut self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>, proof: &Proof<S>) {
        let entry = Self::prepare(ios, ad, proof);
        self.push_prepared(entry);
    }

    /// Batch-verify multiple Pedersen proofs using a single multi-scalar multiplication.
    ///
    /// For each proof i, two equations are checked with independent random scalars
    /// t_i (eq1) and u_i (eq2):
    ///   Eq1: O_i*c_i + Ok_i == I_i*s_i
    ///   Eq2: Yb_i*c_i + R_i == G*s_i + B*sb_i
    ///
    /// The random linear combination yields a (5N + 2)-point MSM.
    ///
    /// Returns `Ok(())` if all proofs verify, `Err(VerificationFailure)` otherwise.
    pub fn verify(&self) -> Result<(), Error> {
        let items = &self.items;
        if items.is_empty() {
            return Ok(());
        }

        let n = items.len();

        // Generate deterministic random scalars from entry data.
        // Absorb (c, s, sb) per entry, then squeeze 2N random scalars.
        // The challenge c already commits to (Yb, I, O, R, Ok, ad), so only the
        // response scalars s and sb need to be included separately.
        let mut t = S::Transcript::new(S::SUITE_ID);
        t.absorb_raw(&[DomSep::PedersenBatch as u8]);
        for e in items {
            t.absorb_serialize(&e.c);
            t.absorb_serialize(&e.s);
            t.absorb_serialize(&e.sb);
        }
        // Sample 2N random 128-bit scalars (t_i for eq1, u_i for eq2).
        // 128-bit scalars are sufficient for the Schwartz-Zippel soundness argument
        // (error probability 2^{-128}) and roughly halve the MSM cost compared to
        // full-width field elements, since fewer doublings are needed in the
        // Pippenger/Straus window.
        let random_scalars: Vec<(ScalarField<S>, ScalarField<S>)> = (0..n)
            .map(|_| {
                let mut buf = [0u8; 32];
                t.squeeze_raw(&mut buf);
                let t = ScalarField::<S>::from_le_bytes_mod_order(&buf[..16]);
                let u = ScalarField::<S>::from_le_bytes_mod_order(&buf[16..]);
                (t, u)
            })
            .collect();

        // Build MSM: 5N per-proof points + 2 shared bases (G, B)
        let mut bases = Vec::with_capacity(5 * n + 2);
        let mut scalars = Vec::with_capacity(5 * n + 2);

        let mut g_scalar = ScalarField::<S>::zero();
        let mut b_scalar = ScalarField::<S>::zero();

        for (e, (t, u)) in items.iter().zip(random_scalars.iter()) {
            // Eq1: t_i*c_i*O_i + t_i*Ok_i - t_i*s_i*I_i = 0
            bases.push(e.output);
            scalars.push(*t * e.c);

            bases.push(e.ok);
            scalars.push(*t);

            bases.push(e.input);
            scalars.push(-(*t * e.s));

            // Eq2: u_i*c_i*Yb_i + u_i*R_i - u_i*s_i*G - u_i*sb_i*B = 0
            bases.push(e.pk_com);
            scalars.push(*u * e.c);

            bases.push(e.r);
            scalars.push(*u);

            // Accumulate shared base scalars
            g_scalar += *u * e.s;
            b_scalar += *u * e.sb;
        }

        // Shared bases: G and B
        bases.push(S::generator());
        scalars.push(-g_scalar);

        bases.push(S::BLINDING_BASE);
        scalars.push(-b_scalar);

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
    use crate::testing::{self as common, CheckPoint, SuiteExt, TEST_SEED, random_val};

    pub fn prove_verify<S: PedersenSuite>() {
        use pedersen::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);

        let (proof, blinding) = secret.prove(io, b"foo");
        let result = Public::verify(io, b"foo", &proof);
        assert!(result.is_ok());

        assert_eq!(
            proof.key_commitment(),
            (secret.public().0 + S::BLINDING_BASE * blinding).into()
        );
    }

    pub fn batch_verify<S: PedersenSuite>() {
        use pedersen::{BatchVerifier, Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);

        let (proof1, _) = secret.prove(io, b"foo");
        let (proof2, _) = secret.prove(io, b"bar");

        // Single-proof verification still works.
        assert!(Public::verify(io, b"foo", &proof1).is_ok());
        assert!(Public::verify(io, b"bar", &proof2).is_ok());

        // Batch using push.
        let mut batch = BatchVerifier::new();
        batch.push(io, b"foo", &proof1);
        batch.push(io, b"bar", &proof2);
        assert!(batch.verify().is_ok());

        // Batch using prepare + push_prepared.
        let mut batch = BatchVerifier::new();
        let entry1 = BatchVerifier::prepare(io, b"foo", &proof1);
        let entry2 = BatchVerifier::prepare(io, b"bar", &proof2);
        batch.push_prepared(entry1);
        batch.push_prepared(entry2);
        assert!(batch.verify().is_ok());

        // Empty batch is ok.
        let batch = BatchVerifier::<S>::new();
        assert!(batch.verify().is_ok());

        // Bad additional data should fail.
        let mut batch = BatchVerifier::new();
        batch.push(io, b"foo", &proof1);
        batch.push(io, b"wrong", &proof2);
        assert!(batch.verify().is_err());
    }

    /// N=1 slice produces same proof as passing a single `VrfIo`.
    pub fn prove_verify_multi_single<S: PedersenSuite>() {
        use pedersen::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(None));
        let io = secret.vrf_io(input);

        let (proof_single, blinding_single) = secret.prove(io, b"foo");
        let (proof_slice, blinding_slice) = secret.prove([io], b"foo");

        // Byte-identical proofs and blinding factors
        let encode = |p: &pedersen::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));
        assert_eq!(blinding_single, blinding_slice);

        // Cross-verification
        assert!(Public::verify(io, b"foo", &proof_slice).is_ok());
        assert!(Public::verify([io], b"foo", &proof_single).is_ok());
    }

    /// N=3 multi proof: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: PedersenSuite>() {
        use pedersen::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);

        let mut ios: Vec<VrfIo<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                secret.vrf_io(input)
            })
            .collect();
        ios.push(VrfIo {
            input: Input(S::Affine::generator()),
            output: Output(secret.public().0),
        });

        let (proof, _) = secret.prove(&ios[..], b"bar");
        assert!(Public::verify(&ios[..], b"bar", &proof).is_ok());

        // Tamper: wrong output on ios[1]
        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(Public::verify(&bad_ios[..], b"bar", &proof).is_err());

        // Tamper: wrong input on ios[0]
        let mut bad_ios = ios.clone();
        bad_ios[0].input = ios[1].input;
        assert!(Public::verify(&bad_ios[..], b"bar", &proof).is_err());

        // Tamper: wrong ad
        assert!(Public::verify(&ios[..], b"baz", &proof).is_err());
    }

    /// N=0 reduces to a Schnorr signature over the additional data.
    pub fn prove_verify_multi_empty<S: PedersenSuite>() {
        use pedersen::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);

        let ios: [VrfIo<S>; 0] = [];
        let (proof, _) = secret.prove(ios, b"bar");

        assert!(Public::verify(ios, b"bar", &proof).is_ok());

        // Wrong ad should fail
        assert!(Public::verify(ios, b"baz", &proof).is_err());
    }

    pub fn blinding_base_check<S: PedersenSuite>()
    where
        AffinePoint<S>: CheckPoint,
    {
        // Check that point has been computed using the magic spell.
        assert_eq!(
            S::BLINDING_BASE,
            S::data_to_point(PEDERSEN_BLINDING_BASE_SEED).unwrap()
        );
        // Check that the point is on curve.
        assert!(S::BLINDING_BASE.check(true).is_ok());
    }

    #[macro_export]
    macro_rules! pedersen_suite_tests {
        ($suite:ty) => {
            mod pedersen {
                use super::*;

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
                fn batch_verify() {
                    $crate::pedersen::testing::batch_verify::<$suite>();
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
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, ad);
            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(base.h),
                output: Output::from_affine_unchecked(base.gamma),
            };
            let secret = Secret::from_scalar(base.sk);
            let (proof, blind) = secret.prove(io, ad);
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
            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(self.base.h),
                output: Output::from_affine_unchecked(self.base.gamma),
            };
            let sk = Secret::from_scalar(self.base.sk);
            let (proof, blind) = sk.prove(io, &self.base.ad);
            assert_eq!(self.blind, blind, "Blinding factor mismatch");
            assert_eq!(self.proof.pk_com, proof.pk_com, "Proof pkb mismatch");
            assert_eq!(self.proof.r, proof.r, "Proof r mismatch");
            assert_eq!(self.proof.ok, proof.ok, "Proof ok mismatch");
            assert_eq!(self.proof.s, proof.s, "Proof s mismatch");
            assert_eq!(self.proof.sb, proof.sb, "Proof sb mismatch");

            assert!(Public::verify(io, &self.base.ad, &proof).is_ok());
        }
    }
}
