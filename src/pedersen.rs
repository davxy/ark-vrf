//! # Pedersen-VRF
//!
//! Implementation of a key-hiding VRF scheme using Pedersen commitments as described in
//! [BCHSV23](https://eprint.iacr.org/2023/002).
//!
//! This scheme extends the IETF VRF by adding key privacy through blinding factors,
//! allowing verification without revealing which specific public key was used.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! // Key generation
//! let secret = Secret::<MySuite>::from_seed(b"seed");
//! let public = secret.public();
//!
//! // Proving
//! use ark_vrf::pedersen::Prover;
//! let input = Input::from(my_data);
//! let output = secret.output(input);
//! let (proof, blinding) = secret.prove(input, output, aux_data);
//!
//! // Verification
//! use ark_vrf::pedersen::Verifier;
//! let result = Public::verify(input, output, aux_data, &proof);
//!
//! // Verify the proof was created using a specific public key
//! // This requires knowledge of the blinding factor
//! let expected_commitment = (public.0 + MySuite::BLINDING_BASE * blinding).into_affine();
//! assert_eq!(proof.key_commitment(), expected_commitment);
//! ```

use crate::ietf::IetfSuite;
use crate::*;
use ark_ec::VariableBaseMSM;

/// Magic spell for [`PedersenSuite::BLINDING_BASE`] generation in built-in implementations.
///
/// (en) *"the blinding foundation of hidden light which eludes the mind and creates darkness for those who see"*
pub const PEDERSEN_BASE_SEED: &[u8] =
    b"basis caecans lucis occultae quae mentem fugit et tenebras iis qui vident creat";

pub trait PedersenSuite: IetfSuite {
    /// Blinding base.
    const BLINDING_BASE: AffinePoint<Self>;

    /// Pedersen blinding factor.
    ///
    /// Default implementation is deterministic and loosely inspired by the RFC-9381
    /// challenge procedure. All parameters but `secret` are public.
    fn blinding(
        secret: &ScalarField<Self>,
        input: &AffinePoint<Self>,
        aux: &[u8],
    ) -> ScalarField<Self> {
        const DOM_SEP_START: u8 = 0xCC;
        const DOM_SEP_END: u8 = 0x00;
        let mut buf = [Self::SUITE_ID, &[DOM_SEP_START]].concat();
        Self::Codec::scalar_encode_into(secret, &mut buf);
        Self::Codec::point_encode_into(input, &mut buf);
        buf.extend_from_slice(aux);
        buf.push(DOM_SEP_END);
        let hash = &utils::hash::<Self::Hasher>(&buf);
        ScalarField::<Self>::from_be_bytes_mod_order(hash)
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

/// Deferred Pedersen verification data for batch verification.
///
/// Captures all the information needed to verify a single Pedersen proof,
/// allowing multiple proofs to be verified together via a single MSM.
pub struct BatchEntry<S: PedersenSuite> {
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
pub struct BatchVerifier<S: PedersenSuite> {
    items: Vec<BatchEntry<S>>,
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
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> BatchEntry<S> {
        let c = S::challenge(
            &[&proof.pk_com, &input.0, &output.0, &proof.r, &proof.ok],
            ad.as_ref(),
        );
        BatchEntry {
            c,
            input: input.0,
            output: output.0,
            pk_com: proof.pk_com,
            r: proof.r,
            ok: proof.ok,
            s: proof.s,
            sb: proof.sb,
        }
    }

    /// Push a previously prepared entry into the batch.
    pub fn push_prepared(&mut self, entry: BatchEntry<S>) {
        self.items.push(entry);
    }

    /// Prepare and push a proof in one step.
    pub fn push(
        &mut self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) {
        let entry = Self::prepare(input, output, ad, proof);
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
        // Hash (c, s, sb) per entry into a seed, then use ChaCha20Rng to sample 2N scalars.
        // The challenge c already commits to (Yb, I, O, R, Ok, ad), so only the
        // response scalars s and sb need to be included separately.
        let mut hasher = S::Hasher::new();
        let mut buf = Vec::new();
        for e in items {
            buf.clear();
            S::Codec::scalar_encode_into(&e.c, &mut buf);
            S::Codec::scalar_encode_into(&e.s, &mut buf);
            S::Codec::scalar_encode_into(&e.sb, &mut buf);
            hasher.update(&buf);
        }
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        let copy_len = hash.len().min(32);
        seed[..copy_len].copy_from_slice(&hash[..copy_len]);

        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        // Sample 2N random scalars (t_i for eq1, u_i for eq2)
        let random_scalars: Vec<(ScalarField<S>, ScalarField<S>)> = (0..n)
            .map(|_| {
                use ark_std::UniformRand;
                (
                    ScalarField::<S>::rand(&mut rng),
                    ScalarField::<S>::rand(&mut rng),
                )
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

/// Trait for types that can generate Pedersen VRF proofs.
///
/// Implementors can create zero-knowledge proofs that a VRF output
/// is correctly derived from an input using their secret key,
/// while hiding the specific public key used.
pub trait Prover<S: PedersenSuite> {
    /// Generate a proof for the given input/output and additional data.
    ///
    /// Creates a zero-knowledge proof binding the input, output, and additional data
    /// to a commitment of the prover's public key rather than the key itself.
    ///
    /// * `input` - VRF input point
    /// * `output` - VRF output point (γ = x·H)
    /// * `ad` - Additional data to bind to the proof
    ///
    /// Returns the proof together with the associated blinding factor.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>);
}

/// Trait for entities that can verify Pedersen VRF proofs.
///
/// Implementors can verify that a VRF output is correctly derived
/// from an input using a committed public key.
pub trait Verifier<S: PedersenSuite> {
    /// Verify a proof for the given input/output and additional data.
    ///
    /// Verifies the cryptographic relationship between input, output, and proof
    /// without requiring knowledge of which specific public key was used.
    /// Confirms that the secret key used to generate the output is the same as
    /// the one committed to in the proof.
    ///
    /// * `input` - VRF input point
    /// * `output` - Claimed VRF output point
    /// * `ad` - Additional data bound to the proof
    /// * `proof` - The proof to verify
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::VerificationFailure)` otherwise.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: PedersenSuite> Prover<S> for Secret<S> {
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>) {
        // Build blinding factor
        let blinding = S::blinding(&self.scalar, &input.0, ad.as_ref());

        // Construct the nonces
        let k = S::nonce(&self.scalar, input);
        let kb = S::nonce(&blinding, input);

        // Yb = x*G + b*B
        let xg = smul!(S::generator(), self.scalar);
        let bb = smul!(S::BLINDING_BASE, blinding);
        let pk_com = xg + bb;

        // R = k*G + kb*B
        let kg = smul!(S::generator(), k);
        let kbb = smul!(S::BLINDING_BASE, kb);
        let r = kg + kbb;

        // Ok = k*I
        let ok = smul!(input.0, k);

        let norms = CurveGroup::normalize_batch(&[pk_com, r, ok]);
        let (pk_com, r, ok) = (norms[0], norms[1], norms[2]);

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[&pk_com, &input.0, &output.0, &r, &ok], ad.as_ref());

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
        input: Input<S>,
        output: Output<S>,
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

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[pk_com, &input.0, &output.0, r, ok], ad.as_ref());

        // Eq1: Ok + c*O = s*I
        // Verifies that the VRF output O is correctly derived from the input I
        // using the same secret scalar x committed in the proof. Expanding the
        // response s = k + c*x gives s*I = k*I + c*x*I = Ok + c*O.
        if output.0 * c + ok != input.0 * s {
            return Err(Error::VerificationFailure);
        }

        // Eq2: R + c*Yb = s*G + sb*B
        // Verifies knowledge of both the secret key x and blinding factor b
        // committed in the public key commitment Yb = x*G + b*B. Expanding
        // s = k + c*x and sb = kb + c*b gives s*G + sb*B = R + c*Yb.
        if *pk_com * c + r != S::generator() * s + S::BLINDING_BASE * sb {
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
        let input = Input::from(random_val(None));
        let output = secret.output(input);

        let (proof, blinding) = secret.prove(input, output, b"foo");
        let result = Public::verify(input, output, b"foo", &proof);
        assert!(result.is_ok());

        assert_eq!(
            proof.key_commitment(),
            (secret.public().0 + S::BLINDING_BASE * blinding).into()
        );
    }

    pub fn batch_verify<S: PedersenSuite>() {
        use pedersen::{BatchVerifier, Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let input = Input::from(random_val(None));
        let output = secret.output(input);

        let (proof1, _) = secret.prove(input, output, b"foo");
        let (proof2, _) = secret.prove(input, output, b"bar");

        // Single-proof verification still works.
        assert!(Public::verify(input, output, b"foo", &proof1).is_ok());
        assert!(Public::verify(input, output, b"bar", &proof2).is_ok());

        // Batch using push.
        let mut batch = BatchVerifier::new();
        batch.push(input, output, b"foo", &proof1);
        batch.push(input, output, b"bar", &proof2);
        assert!(batch.verify().is_ok());

        // Batch using prepare + push_prepared.
        let mut batch = BatchVerifier::new();
        let entry1 = BatchVerifier::prepare(input, output, b"foo", &proof1);
        let entry2 = BatchVerifier::prepare(input, output, b"bar", &proof2);
        batch.push_prepared(entry1);
        batch.push_prepared(entry2);
        assert!(batch.verify().is_ok());

        // Empty batch is ok.
        let batch = BatchVerifier::<S>::new();
        assert!(batch.verify().is_ok());

        // Bad additional data should fail.
        let mut batch = BatchVerifier::new();
        batch.push(input, output, b"foo", &proof1);
        batch.push(input, output, b"wrong", &proof2);
        assert!(batch.verify().is_err());
    }

    pub fn blinding_base_check<S: PedersenSuite>()
    where
        AffinePoint<S>: CheckPoint,
    {
        // Check that point has been computed using the magic spell.
        assert_eq!(
            S::BLINDING_BASE,
            S::data_to_point(PEDERSEN_BASE_SEED).unwrap()
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
            S::suite_name() + "_pedersen"
        }

        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, salt, ad);
            let input = Input::<S>::from(base.h);
            let output = Output::from(base.gamma);
            let secret = Secret::from_scalar(base.sk);
            let (proof, blind) = secret.prove(input, output, ad);
            Self { base, blind, proof }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let blind = S::Codec::scalar_decode(&map.get_bytes("blinding"));
            let pk_com = S::Codec::point_decode(&map.get_bytes("proof_pk_com")).unwrap();
            let r = codec::point_decode::<S>(&map.get_bytes("proof_r")).unwrap();
            let ok = codec::point_decode::<S>(&map.get_bytes("proof_ok")).unwrap();
            let s = S::Codec::scalar_decode(&map.get_bytes("proof_s"));
            let sb = S::Codec::scalar_decode(&map.get_bytes("proof_sb"));
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
                    hex::encode(codec::scalar_encode::<S>(&self.blind)),
                ),
                (
                    "proof_pk_com",
                    hex::encode(codec::point_encode::<S>(&self.proof.pk_com)),
                ),
                (
                    "proof_r",
                    hex::encode(codec::point_encode::<S>(&self.proof.r)),
                ),
                (
                    "proof_ok",
                    hex::encode(codec::point_encode::<S>(&self.proof.ok)),
                ),
                (
                    "proof_s",
                    hex::encode(codec::scalar_encode::<S>(&self.proof.s)),
                ),
                (
                    "proof_sb",
                    hex::encode(codec::scalar_encode::<S>(&self.proof.sb)),
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
            let input = Input::<S>::from(self.base.h);
            let output = Output::from(self.base.gamma);
            let sk = Secret::from_scalar(self.base.sk);
            let (proof, blind) = sk.prove(input, output, &self.base.ad);
            assert_eq!(self.blind, blind, "Blinding factor mismatch");
            assert_eq!(self.proof.pk_com, proof.pk_com, "Proof pkb mismatch");
            assert_eq!(self.proof.r, proof.r, "Proof r mismatch");
            assert_eq!(self.proof.ok, proof.ok, "Proof ok mismatch");
            assert_eq!(self.proof.s, proof.s, "Proof s mismatch");
            assert_eq!(self.proof.sb, proof.sb, "Proof sb mismatch");

            assert!(Public::verify(input, output, &self.base.ad, &proof).is_ok());
        }
    }
}
