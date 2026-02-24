//! # Batch-Compatible ECVRF
//!
//! Implementation of the batch-compatible ECVRF scheme (ECVRF_bc) as described in
//! ["On UC-Secure Range Extension and Batch Verification for ECVRF"](https://eprint.iacr.org/2022/1045).
//!
//! The standard ECVRF proof contains `(c, s)` where `c` is the Fiat-Shamir challenge.
//! The verifier must reconstruct the nonce commitments `U = s*G - c*pk` and
//! `V = s*H - c*Gamma` before recomputing `c`, making the verification equations implicit.
//!
//! ECVRF_bc instead includes the nonce commitments directly in the proof as `(U, V, s)`,
//! turning verification into explicit equality checks that can be batched via a single
//! multi-scalar multiplication across `n` proofs.
//!
//! Trade-off: proof size grows (e.g. 48 -> 96 bytes for ed25519) but batch verification
//! of many proofs achieves significant speedups.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! // Key generation
//! let secret = Secret::<MySuite>::from_seed(b"seed");
//! let public = secret.public();
//!
//! // Proving
//! use ark_vrf::ietf_bc::Prover;
//! let input = Input::from_affine(my_data);
//! let output = secret.output(input);
//! let proof = secret.prove(input, output, aux_data);
//!
//! // Single verification
//! use ark_vrf::ietf_bc::Verifier;
//! let result = public.verify(input, output, aux_data, &proof);
//!
//! // Batch verification
//! use ark_vrf::ietf_bc::BatchVerifier;
//! let mut batch = BatchVerifier::new();
//! batch.push(&public, input, output, aux_data, &proof);
//! batch.verify().unwrap();
//! ```

use super::*;
use ark_ec::VariableBaseMSM;

/// Batch-compatible ECVRF proof.
///
/// Stores the nonce commitments directly instead of the challenge scalar,
/// enabling efficient batch verification:
/// - `u`: Nonce commitment k*G
/// - `v`: Nonce commitment k*H
/// - `s`: Response scalar
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: Suite> {
    /// Nonce commitment: k*G.
    pub u: AffinePoint<S>,
    /// Nonce commitment: k*H.
    pub v: AffinePoint<S>,
    /// Response scalar.
    pub s: ScalarField<S>,
}

/// Trait for types that can generate batch-compatible VRF proofs.
pub trait Prover<S: Suite> {
    /// Generate a batch-compatible proof for the given input/output and additional data.
    ///
    /// * `input` - VRF input point
    /// * `output` - VRF output point
    /// * `ad` - Additional data to bind to the proof
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for entities that can verify batch-compatible VRF proofs.
pub trait Verifier<S: Suite> {
    /// Verify a batch-compatible proof for the given input/output and additional data.
    ///
    /// * `input` - VRF input point
    /// * `output` - Claimed VRF output point
    /// * `ad` - Additional data bound to the proof
    /// * `proof` - The proof to verify
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::VerificationFailure)` otherwise.
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: Suite> Prover<S> for Secret<S> {
    /// Implements the batch-compatible ECVRF proving algorithm.
    ///
    /// 1. Generate a deterministic nonce `k` based on the secret key and input
    /// 2. Compute nonce commitments `U = k*G` and `V = k*H`
    /// 3. Compute the challenge `c` using all public values and nonce commitments
    /// 4. Compute the response `s = k + c * secret`
    /// 5. Return proof `(U, V, s)` instead of `(c, s)`
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let k = S::nonce(&self.scalar, input);

        let u = smul!(S::generator(), k);
        let v = smul!(input.0, k);
        let norms = CurveGroup::normalize_batch(&[u, v]);
        let (u, v) = (norms[0], norms[1]);

        let c = S::challenge(
            &[&self.public.0, &input.0, &output.0, &u, &v],
            ad.as_ref(),
        );
        let s = k + c * self.scalar;
        Proof { u, v, s }
    }
}

impl<S: Suite> Verifier<S> for Public<S> {
    /// Implements the batch-compatible ECVRF verification algorithm.
    ///
    /// 1. Recompute `c = challenge(pk, H, Gamma, U, V, ad)`
    /// 2. Check `U + c*pk == s*G`  (equivalently: `proof.u == s*G - c*pk`)
    /// 3. Check `V + c*Gamma == s*H`  (equivalently: `proof.v == s*H - c*Gamma`)
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof { u, v, s } = proof;

        let c = S::challenge(&[&self.0, &input.0, &output.0, u, v], ad.as_ref());

        // U + c*pk == s*G
        if *u + self.0 * c != S::generator() * s {
            return Err(Error::VerificationFailure);
        }

        // V + c*Gamma == s*H
        if *v + output.0 * c != input.0 * s {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

/// Deferred batch-compatible verification data for batch verification.
///
/// Captures all the information needed to verify a single proof,
/// allowing multiple proofs to be verified together via a single MSM.
pub struct BatchItem<S: Suite> {
    c: ScalarField<S>,
    pk: AffinePoint<S>,
    input: AffinePoint<S>,
    output: AffinePoint<S>,
    u: AffinePoint<S>,
    v: AffinePoint<S>,
    s: ScalarField<S>,
}

/// Batch verifier for batch-compatible ECVRF proofs.
///
/// Collects multiple proofs and verifies them together via a single
/// multi-scalar multiplication, following Section 8.2 of the paper.
pub struct BatchVerifier<S: Suite> {
    items: Vec<BatchItem<S>>,
}

impl<S: Suite> Default for BatchVerifier<S> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}

impl<S: Suite> BatchVerifier<S> {
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
        pk: &Public<S>,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> BatchItem<S> {
        let c = S::challenge(
            &[&pk.0, &input.0, &output.0, &proof.u, &proof.v],
            ad.as_ref(),
        );
        BatchItem {
            c,
            pk: pk.0,
            input: input.0,
            output: output.0,
            u: proof.u,
            v: proof.v,
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
        pk: &Public<S>,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) {
        let entry = Self::prepare(pk, input, output, ad, proof);
        self.push_prepared(entry);
    }

    /// Batch-verify multiple proofs using a single multi-scalar multiplication.
    ///
    /// Follows Section 8.2 of the paper:
    /// 1. Build transcript `S_T` = concatenation of `(H_i || proof_i)` for all items.
    /// 2. For each item, derive `h_i = Hash(suite_s || 0x04 || S_T || i_le_bytes || 0x00)`.
    /// 3. Split `h_i` into `l_i` and `r_i`, interpreted as LE integers.
    /// 4. Build MSM (5n + 1 points):
    ///    - Per proof: `pk_i` (scalar: `-r_i*c_i`), `U_i` (scalar: `-r_i`),
    ///      `H_i` (scalar: `l_i*s_i`), `Gamma_i` (scalar: `-l_i*c_i`), `V_i` (scalar: `-l_i`)
    ///    - Shared: `G` (scalar: `sum(r_i * s_i)`)
    /// 5. Check MSM result == zero.
    pub fn verify(&self) -> Result<(), Error> {
        use digest::Digest;

        let items = &self.items;
        if items.is_empty() {
            return Ok(());
        }

        let n = items.len();

        // Step 1: Build transcript S_T = concat(H_i || proof_i) for all items.
        // H_i is the input point, proof_i is (U_i, V_i, s_i).
        let mut transcript = Vec::new();
        let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
        for e in items {
            pt_buf.clear();
            S::Codec::point_encode_into(&e.input, &mut pt_buf);
            transcript.extend_from_slice(&pt_buf);
            pt_buf.clear();
            S::Codec::point_encode_into(&e.u, &mut pt_buf);
            transcript.extend_from_slice(&pt_buf);
            pt_buf.clear();
            S::Codec::point_encode_into(&e.v, &mut pt_buf);
            transcript.extend_from_slice(&pt_buf);
            let mut sc_buf = Vec::with_capacity(S::Codec::SCALAR_ENCODED_LEN);
            S::Codec::scalar_encode_into(&e.s, &mut sc_buf);
            transcript.extend_from_slice(&sc_buf);
        }

        // Step 2: For each item, derive h_i and split into l_i, r_i.
        let clen = S::CHALLENGE_LEN;

        let mut bases = Vec::with_capacity(5 * n + 1);
        let mut scalars = Vec::with_capacity(5 * n + 1);
        let mut g_scalar = ScalarField::<S>::zero();

        for (i, e) in items.iter().enumerate() {
            // h_i = Hash(suite_s || 0x04 || S_T || i_le_bytes || 0x00)
            let h_i = S::Hasher::new()
                .chain_update(S::SUITE_ID)
                .chain_update([0x04])
                .chain_update(&transcript)
                .chain_update((i as u32).to_le_bytes())
                .chain_update([0x00])
                .finalize();

            // Split h_i into l_i and r_i (each CHALLENGE_LEN bytes, LE integers).
            let l_i =
                ScalarField::<S>::from_le_bytes_mod_order(&h_i[..clen]);
            let r_i =
                ScalarField::<S>::from_le_bytes_mod_order(&h_i[clen..2 * clen]);

            // Per-proof bases and scalars:
            // pk_i with scalar -r_i*c_i
            bases.push(e.pk);
            scalars.push(-(r_i * e.c));

            // U_i with scalar -r_i
            bases.push(e.u);
            scalars.push(-r_i);

            // H_i (input) with scalar l_i*s_i
            bases.push(e.input);
            scalars.push(l_i * e.s);

            // Gamma_i (output) with scalar -l_i*c_i
            bases.push(e.output);
            scalars.push(-(l_i * e.c));

            // V_i with scalar -l_i
            bases.push(e.v);
            scalars.push(-l_i);

            // Accumulate shared G scalar: sum(r_i * s_i)
            g_scalar += r_i * e.s;
        }

        // Shared base: G
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
pub mod testing {
    use super::*;
    use crate::testing::{self as common, SuiteExt};

    pub fn prove_verify<S: Suite>() {
        use ietf_bc::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(common::random_val(None));
        let output = secret.output(input);

        let proof = secret.prove(input, output, b"foo");
        let result = public.verify(input, output, b"foo", &proof);
        assert!(result.is_ok());
    }

    pub fn batch_verify<S: Suite>() {
        use ietf_bc::{BatchVerifier, Prover, Verifier};

        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine(common::random_val(None));
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
    macro_rules! ietf_bc_suite_tests {
        ($suite:ty) => {
            mod ietf_bc {
                use super::*;

                #[test]
                fn prove_verify() {
                    $crate::ietf_bc::testing::prove_verify::<$suite>();
                }

                #[test]
                fn batch_verify() {
                    $crate::ietf_bc::testing::batch_verify::<$suite>();
                }

                $crate::test_vectors!($crate::ietf_bc::testing::TestVector<$suite>);
            }
        };
    }

    pub struct TestVector<S: Suite> {
        pub base: common::TestVector<S>,
        pub u: AffinePoint<S>,
        pub v: AffinePoint<S>,
        pub s: ScalarField<S>,
    }

    impl<S: Suite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let u = hex::encode(codec::point_encode::<S>(&self.u));
            let v = hex::encode(codec::point_encode::<S>(&self.v));
            let s = hex::encode(codec::scalar_encode::<S>(&self.s));
            f.debug_struct("TestVector")
                .field("base", &self.base)
                .field("proof_u", &u)
                .field("proof_v", &v)
                .field("proof_s", &s)
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: Suite + SuiteExt + std::fmt::Debug,
    {
        fn name() -> String {
            S::suite_name() + "_ietf_bc"
        }

        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, salt, ad);
            let input = Input::from_affine(base.h);
            let output = Output::from_affine(base.gamma);
            let sk = Secret::from_scalar(base.sk);
            let proof: Proof<S> = sk.prove(input, output, ad);
            Self {
                base,
                u: proof.u,
                v: proof.v,
                s: proof.s,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let u = codec::point_decode::<S>(&map.get_bytes("proof_u")).unwrap();
            let v = codec::point_decode::<S>(&map.get_bytes("proof_v")).unwrap();
            let s = S::Codec::scalar_decode(&map.get_bytes("proof_s"));
            Self { base, u, v, s }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let items = [
                ("proof_u", hex::encode(codec::point_encode::<S>(&self.u))),
                ("proof_v", hex::encode(codec::point_encode::<S>(&self.v))),
                ("proof_s", hex::encode(codec::scalar_encode::<S>(&self.s))),
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
            assert_eq!(self.u, proof.u, "VRF proof nonce commitment U mismatch");
            assert_eq!(self.v, proof.v, "VRF proof nonce commitment V mismatch");
            assert_eq!(self.s, proof.s, "VRF proof response ('s') mismatch");

            let pk = Public(self.base.pk);
            assert!(pk.verify(input, output, &self.base.ad, &proof).is_ok());
        }
    }
}
