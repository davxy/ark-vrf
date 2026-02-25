//! # Thin-VRF
//!
//! Implementation of the Thin VRF scheme as described in the
//! [W3F ring-vrf specification](https://github.com/davxy/bandersnatch-vrf-spec).
//!
//! ThinVrf merges the public-key Schnorr pair `(G, P)` and the VRF I/O pair
//! `(I, O)` into a single DLEQ relation via delinearization, then proves it
//! with a Schnorr-like proof `(R, s)`. The `(R, s)` format (storing nonce
//! commitment rather than challenge) enables batch verification.
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
//! let output = secret.output(input);
//!
//! // Proving
//! let proof = secret.prove(input, output, b"aux data");
//!
//! // Verification
//! let result = public.verify(input, output, b"aux data", &proof);
//! ```

use crate::*;
use ark_ec::VariableBaseMSM;

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

/// Compute delinearization weights `(z_0, z_1)` for the VRF I/O and Schnorr pairs.
///
/// Hashes `(G, P, I, O)` with domain separator `0x11` and splits the output
/// into two 128-bit scalars used to merge the two DLEQ relations.
fn delinearize<S: ThinVrfSuite>(
    public: &AffinePoint<S>,
    input: &AffinePoint<S>,
    output: &AffinePoint<S>,
) -> (ScalarField<S>, ScalarField<S>) {
    use digest::Digest;

    const DOM_SEP_START: u8 = 0x11;
    const DOM_SEP_END: u8 = 0x00;

    let mut buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    let hash = S::Hasher::new()
        .chain_update(S::SUITE_ID)
        .chain_update([DOM_SEP_START])
        .chain_update({
            S::Codec::point_encode_into(&S::generator(), &mut buf);
            &buf
        })
        .chain_update({
            buf.clear();
            S::Codec::point_encode_into(public, &mut buf);
            &buf
        })
        .chain_update({
            buf.clear();
            S::Codec::point_encode_into(input, &mut buf);
            &buf
        })
        .chain_update({
            buf.clear();
            S::Codec::point_encode_into(output, &mut buf);
            &buf
        })
        .chain_update([DOM_SEP_END])
        .finalize();

    let z_0 = ScalarField::<S>::from_le_bytes_mod_order(&hash[..16]);
    let z_1 = ScalarField::<S>::from_le_bytes_mod_order(&hash[16..32]);
    (z_0, z_1)
}

/// Compute the Thin VRF challenge.
///
/// Follows the RFC-9381 challenge pattern with domain separator `0x12`.
fn thin_challenge<S: ThinVrfSuite>(
    public: &AffinePoint<S>,
    input: &AffinePoint<S>,
    output: &AffinePoint<S>,
    r: &AffinePoint<S>,
    ad: &[u8],
) -> ScalarField<S> {
    use digest::Digest;

    const DOM_SEP_START: u8 = 0x12;
    const DOM_SEP_END: u8 = 0x00;

    let mut buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    let mut hasher = S::Hasher::new();
    hasher.update(S::SUITE_ID);
    hasher.update([DOM_SEP_START]);

    S::Codec::point_encode_into(public, &mut buf);
    hasher.update(&buf);

    buf.clear();
    S::Codec::point_encode_into(input, &mut buf);
    hasher.update(&buf);

    buf.clear();
    S::Codec::point_encode_into(output, &mut buf);
    hasher.update(&buf);

    buf.clear();
    S::Codec::point_encode_into(r, &mut buf);
    hasher.update(&buf);

    hasher.update(ad);
    hasher.update([DOM_SEP_END]);

    let hash = hasher.finalize();
    ScalarField::<S>::from_be_bytes_mod_order(&hash[..S::CHALLENGE_LEN])
}

/// Trait for types that can generate Thin VRF proofs.
pub trait Prover<S: ThinVrfSuite> {
    /// Generate a proof for the given input/output and additional data.
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for entities that can verify Thin VRF proofs.
pub trait Verifier<S: ThinVrfSuite> {
    /// Verify a proof for the given input/output and additional data.
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: ThinVrfSuite> Prover<S> for Secret<S> {
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let (z_0, z_1) = delinearize::<S>(&self.public.0, &input.0, &output.0);

        // Merged pair: I_m = z_0*I + z_1*G, O_m = z_0*O + z_1*P
        let i_m = input.0 * z_0 + S::generator() * z_1;
        let i_m = i_m.into_affine();

        // Nonce
        let k = S::nonce(&self.scalar, Input(i_m));

        // R = k * I_m (secret nonce)
        let r = smul!(i_m, k).into_affine();

        // Challenge
        let c = thin_challenge::<S>(&self.public.0, &input.0, &output.0, &r, ad.as_ref());

        // Response
        let s = k + c * self.scalar;

        Proof { r, s }
    }
}

impl<S: ThinVrfSuite> Verifier<S> for Public<S> {
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof { r, s } = proof;

        let (z_0, z_1) = delinearize::<S>(&self.0, &input.0, &output.0);

        // Merged pair
        let i_m = (input.0 * z_0 + S::generator() * z_1).into_affine();
        let o_m = (output.0 * z_0 + self.0 * z_1).into_affine();

        // Challenge
        let c = thin_challenge::<S>(&self.0, &input.0, &output.0, r, ad.as_ref());

        // Verify: R + c*O_m == s*I_m
        if *r + o_m * c != i_m * s {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

/// Deferred Thin VRF verification data for batch verification.
///
/// Captures all the information needed to verify a single Thin VRF proof,
/// allowing multiple proofs to be verified together via a single MSM.
pub struct BatchItem<S: ThinVrfSuite> {
    c: ScalarField<S>,
    i_m: AffinePoint<S>,
    o_m: AffinePoint<S>,
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
    /// Computes delinearization, merged pair, and challenge. This is cheap
    /// (hashes, no scalar multiplications on secret data) and can be done
    /// in parallel.
    pub fn prepare(
        public: &Public<S>,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> BatchItem<S> {
        let (z_0, z_1) = delinearize::<S>(&public.0, &input.0, &output.0);
        let i_m = (input.0 * z_0 + S::generator() * z_1).into_affine();
        let o_m = (output.0 * z_0 + public.0 * z_1).into_affine();
        let c = thin_challenge::<S>(&public.0, &input.0, &output.0, &proof.r, ad.as_ref());
        BatchItem {
            c,
            i_m,
            o_m,
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
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) {
        let entry = Self::prepare(public, input, output, ad, proof);
        self.push_prepared(entry);
    }

    /// Batch-verify all collected proofs using a single multi-scalar multiplication.
    ///
    /// For each proof i, the verification equation is:
    ///   R_i + c_i*O_m_i - s_i*I_m_i == 0
    ///
    /// With random weights w_i the combined check becomes a 3N-point MSM:
    ///   sum_i w_i*R_i + (w_i*c_i)*O_m_i - (w_i*s_i)*I_m_i == 0
    ///
    /// Returns `Ok(())` if all proofs verify, `Err(VerificationFailure)` otherwise.
    pub fn verify(&self) -> Result<(), Error> {
        use ark_std::rand::{RngCore, SeedableRng};

        let items = &self.items;
        if items.is_empty() {
            return Ok(());
        }

        let n = items.len();

        // Deterministic RNG seeded from all (c, s) pairs.
        let mut hasher = S::Hasher::new();
        let mut buf = Vec::with_capacity(2 * S::Codec::SCALAR_ENCODED_LEN);
        for e in items {
            buf.clear();
            S::Codec::scalar_encode_into(&e.c, &mut buf);
            S::Codec::scalar_encode_into(&e.s, &mut buf);
            hasher.update(&buf);
        }
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        let copy_len = hash.len().min(32);
        seed[..copy_len].copy_from_slice(&hash[..copy_len]);

        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        // 128-bit random weights for Schwartz-Zippel soundness.
        let random_scalars: Vec<ScalarField<S>> = (0..n)
            .map(|_| {
                let mut buf = [0u8; 16];
                rng.fill_bytes(&mut buf);
                ScalarField::<S>::from_le_bytes_mod_order(&buf)
            })
            .collect();

        // Build 3N-point MSM: w_i*R_i + (w_i*c_i)*O_m_i - (w_i*s_i)*I_m_i
        let mut bases = Vec::with_capacity(3 * n);
        let mut scalars = Vec::with_capacity(3 * n);

        for (e, w) in items.iter().zip(random_scalars.iter()) {
            bases.push(e.r);
            scalars.push(*w);

            bases.push(e.o_m);
            scalars.push(*w * e.c);

            bases.push(e.i_m);
            scalars.push(-(*w * e.s));
        }

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

    pub fn prove_verify<S: ThinVrfSuite>() {
        use thin::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(random_val(None));
        let output = secret.output(input);

        let proof = secret.prove(input, output, b"foo");
        let result = public.verify(input, output, b"foo", &proof);
        assert!(result.is_ok());
    }

    pub fn batch_verify<S: ThinVrfSuite>() {
        use thin::{BatchVerifier, Prover, Verifier};

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(random_val(None));
        let output = secret.output(input);

        let proof1 = secret.prove(input, output, b"foo");
        let proof2 = secret.prove(input, output, b"bar");

        // Single-proof verification still works.
        assert!(public.verify(input, output, b"foo", &proof1).is_ok());
        assert!(public.verify(input, output, b"bar", &proof2).is_ok());

        // Batch using push.
        let mut batch = BatchVerifier::new();
        batch.push(&public, input, output, b"foo", &proof1);
        batch.push(&public, input, output, b"bar", &proof2);
        assert!(batch.verify().is_ok());

        // Batch using prepare + push_prepared.
        let mut batch = BatchVerifier::new();
        let entry1 = BatchVerifier::prepare(&public, input, output, b"foo", &proof1);
        let entry2 = BatchVerifier::prepare(&public, input, output, b"bar", &proof2);
        batch.push_prepared(entry1);
        batch.push_prepared(entry2);
        assert!(batch.verify().is_ok());

        // Empty batch is ok.
        let batch = BatchVerifier::<S>::new();
        assert!(batch.verify().is_ok());

        // Bad additional data should fail.
        let mut batch = BatchVerifier::new();
        batch.push(&public, input, output, b"foo", &proof1);
        batch.push(&public, input, output, b"wrong", &proof2);
        assert!(batch.verify().is_err());
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
            let input = Input::<S>::from_affine(base.h);
            let output = Output::from_affine(base.gamma);
            let secret = Secret::from_scalar(base.sk);
            let proof: Proof<S> = secret.prove(input, output, ad);
            Self {
                base,
                proof_r: proof.r,
                proof_s: proof.s,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let proof_r = codec::point_decode::<S>(&map.get_bytes("proof_r")).unwrap();
            let proof_s = S::Codec::scalar_decode(&map.get_bytes("proof_s"));
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
            let input = Input::<S>::from_affine(self.base.h);
            let output = Output::from_affine(self.base.gamma);
            let sk = Secret::from_scalar(self.base.sk);
            let proof = sk.prove(input, output, &self.base.ad);
            assert_eq!(self.proof_r, proof.r, "Thin VRF proof R mismatch");
            assert_eq!(self.proof_s, proof.s, "Thin VRF proof s mismatch");

            let pk = Public(self.base.pk);
            assert!(pk.verify(input, output, &self.base.ad, &proof).is_ok());
        }
    }
}
