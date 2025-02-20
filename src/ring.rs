use crate::*;
use ark_ec::twisted_edwards::{Affine as TEAffine, TECurveConfig};
use pedersen::{PedersenSuite, Proof as PedersenProof};
use utils::te_sw_map::TEMapping;

/// Ring suite.
pub trait RingSuite: PedersenSuite
where
    BaseField<Self>: ark_ff::PrimeField,
    CurveConfig<Self>: TECurveConfig,
    AffinePoint<Self>: TEMapping<CurveConfig<Self>>,
{
    /// Pairing type.
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    /// Accumulator base.
    ///
    /// In order for the ring-proof backend to work correctly, this is required to be
    /// in the prime order subgroup.
    const ACCUMULATOR_BASE: AffinePoint<Self>;

    /// Padding point with unknown discrete log.
    const PADDING: AffinePoint<Self>;
}

/// Polinomial Commitment Scheme (KZG)
type Pcs<S> = ring_proof::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// Single PCS commitment.
type PcsCommitment<S> = ring_proof::pcs::kzg::commitment::KzgCommitment<<S as RingSuite>::Pairing>;

/// KZG "Polynomial Commitment Scheme" (PCS) parameters.
///
/// Basically powers of tau SRS.
pub type PcsParams<S> = ring_proof::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

/// Polynomial "Interactive Oracle Proof" (IOP) parameters.
///
/// Basically all the application specific parameters required to construct and
/// verify the ring proof.
type PiopParams<S> = ring_proof::PiopParams<BaseField<S>, CurveConfig<S>>;

/// Ring keys commitment.
pub type RingCommitment<S> = ring_proof::FixedColumnsCommitted<BaseField<S>, PcsCommitment<S>>;

/// Ring prover key.
pub type ProverKey<S> = ring_proof::ProverKey<BaseField<S>, Pcs<S>, TEAffine<CurveConfig<S>>>;

/// Ring verifier key.
pub type VerifierKey<S> = ring_proof::VerifierKey<BaseField<S>, Pcs<S>>;

/// Ring prover.
pub type RingProver<S> = ring_proof::ring_prover::RingProver<BaseField<S>, Pcs<S>, CurveConfig<S>>;

/// Ring verifier.
pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, Pcs<S>, CurveConfig<S>>;

/// Actual ring proof.
pub type RingProof<S> = ring_proof::RingProof<BaseField<S>, Pcs<S>>;

/// Ring proof bundled together with a Pedersen proof.
///
/// Pedersen proof is used to provide VRF capability.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    pub pedersen_proof: PedersenProof<S>,
    pub ring_proof: RingProof<S>,
}

pub trait Prover<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// Generate a proof for the given input/output and user additional data.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &RingProver<S>,
    ) -> Proof<S>;
}

impl<S: RingSuite> Prover<S> for Secret<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &RingProver<S>,
    ) -> Proof<S> {
        use pedersen::Prover as PedersenProver;
        let (pedersen_proof, secret_blinding) =
            <Self as PedersenProver<S>>::prove(self, input, output, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Proof {
            pedersen_proof,
            ring_proof,
        }
    }
}

pub trait Verifier<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> Verifier<S> for Public<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error> {
        use pedersen::Verifier as PedersenVerifier;
        <Self as PedersenVerifier<S>>::verify(input, output, ad, &sig.pedersen_proof)?;
        let key_commitment = sig.pedersen_proof.key_commitment().into_te();
        if !verifier.verify(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RingContext<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    pcs_params: PcsParams<S>,
    piop_params: PiopParams<S>,
}

// Evaluation domain size required for the given ring size.
#[inline(always)]
fn domain_size<S: RingSuite>(ring_size: usize) -> usize
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    1 << ark_std::log2(ring_size + ScalarField::<S>::MODULUS_BIT_SIZE as usize + 4)
}

#[allow(private_bounds)]
impl<S: RingSuite> RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// Construct a new ring context suitable to manage the given ring size.
    pub fn from_seed(ring_size: usize, seed: [u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::from_rand(ring_size, &mut rng)
    }

    /// Construct a new random ring context suitable for the given ring size.
    pub fn from_rand(ring_size: usize, rng: &mut impl ark_std::rand::RngCore) -> Self {
        use ring_proof::pcs::PCS;
        let domain_size = domain_size::<S>(ring_size);
        let pcs_params = Pcs::<S>::setup(3 * domain_size, rng);
        Self::from_srs(ring_size, pcs_params).expect("PCS params is correct")
    }

    pub fn from_srs(ring_size: usize, mut pcs_params: PcsParams<S>) -> Result<Self, Error> {
        let domain_size = domain_size::<S>(ring_size);
        if pcs_params.powers_in_g1.len() < 3 * domain_size + 1 || pcs_params.powers_in_g2.len() < 2
        {
            return Err(Error::InvalidData);
        }
        // Keep only the required powers of tau.
        pcs_params.powers_in_g1.truncate(3 * domain_size + 1);
        pcs_params.powers_in_g2.truncate(2);

        let piop_params = PiopParams::<S>::setup(
            ring_proof::Domain::new(domain_size, true),
            S::BLINDING_BASE.into_te(),
            S::ACCUMULATOR_BASE.into_te(),
            S::PADDING.into_te(),
        );

        Ok(Self {
            pcs_params,
            piop_params,
        })
    }

    /// The max ring size this context is able to manage.
    #[inline(always)]
    pub fn max_ring_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    /// Construct a `ProverKey` instance for the given ring.
    ///
    /// Note: if `pks.len() > self.max_ring_size()` the extra keys in the tail are ignored.
    pub fn prover_key(&self, pks: &[AffinePoint<S>]) -> ProverKey<S> {
        let pks = TEMapping::to_te_slice(&pks[..pks.len().min(self.max_ring_size())]);
        ring_proof::index(&self.pcs_params, &self.piop_params, &pks).0
    }

    /// Construct `RingProver` from `ProverKey` for the prover implied by `key_index`.
    ///
    /// Key index is the prover index within the `pks` sequence passed to construct the
    /// `ProverKey` via the `prover_key` method.
    pub fn prover(&self, prover_key: ProverKey<S>, key_index: usize) -> RingProver<S> {
        RingProver::<S>::init(
            prover_key,
            self.piop_params.clone(),
            key_index,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Construct a `VerifierKey` instance for the given ring.
    ///
    /// Note: if `pks.len() > self.max_ring_size()` the extra keys in the tail are ignored.
    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> VerifierKey<S> {
        let pks = TEMapping::to_te_slice(&pks[..pks.len().min(self.max_ring_size())]);
        ring_proof::index(&self.pcs_params, &self.piop_params, &pks).1
    }

    /// Construct `VerifierKey` instance for the ring previously committed.
    ///
    /// The `RingCommitment` instance can be obtained via the `VerifierKey::commitment()` method.
    ///
    /// This allows to quickly reconstruct the verifier key without having to recompute the
    /// keys commitment.
    pub fn verifier_key_from_commitment(&self, commitment: RingCommitment<S>) -> VerifierKey<S> {
        use ring_proof::pcs::PcsParams;
        VerifierKey::<S>::from_commitment_and_kzg_vk(commitment, self.pcs_params.raw_vk())
    }

    /// Construct `RingVerifier` from `VerifierKey`.
    pub fn verifier(&self, verifier_key: VerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop_params.clone(),
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Get the padding point.
    #[inline(always)]
    pub const fn padding_point() -> AffinePoint<S> {
        S::PADDING
    }
}

impl<S: RingSuite> CanonicalSerialize for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.pcs_params.serialized_size(compress)
    }
}

impl<S: RingSuite> CanonicalDeserialize for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let pcs_params = <PcsParams<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let domain_size = (pcs_params.powers_in_g1.len() - 1) / 3;
        Self::from_srs(domain_size, pcs_params)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

impl<S: RingSuite> ark_serialize::Valid for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.check()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::pedersen;
    use crate::testing::{self as common, ACCUMULATOR_BASE_SEED, PADDING_SEED, TEST_SEED};

    pub const TEST_RING_SIZE: usize = 8;

    #[allow(unused)]
    pub fn prove_verify<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        let rng = &mut ark_std::test_rng();
        let ring_ctx = RingContext::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(common::random_val(Some(rng)));
        let output = secret.output(input);

        let ring_size = ring_ctx.max_ring_size();

        let prover_idx = 3;
        let mut pks = common::random_vec::<AffinePoint<S>>(ring_size, Some(rng));
        pks[prover_idx] = public.0;

        let prover_key = ring_ctx.prover_key(&pks);
        let prover = ring_ctx.prover(prover_key, prover_idx);
        let proof = secret.prove(input, output, b"foo", &prover);

        let verifier_key = ring_ctx.verifier_key(&pks);
        let verifier = ring_ctx.verifier(verifier_key);
        let result = Public::verify(input, output, b"foo", &proof, &verifier);
        assert!(result.is_ok());
    }

    #[allow(unused)]
    pub fn padding_check<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        let p = S::data_to_point(PADDING_SEED).unwrap();
        assert_eq!(S::PADDING, p);
    }

    #[allow(unused)]
    pub fn accumulator_base_check<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>> + utils::common::FindAccumulatorBase<S>,
    {
        use utils::common::FindAccumulatorBase;
        let p = AffinePoint::<S>::find_accumulator_base(ACCUMULATOR_BASE_SEED).unwrap();
        assert_eq!(S::ACCUMULATOR_BASE, p);
    }

    #[macro_export]
    macro_rules! ring_suite_tests {
        ($suite:ident) => {
            #[test]
            fn ring_prove_verify() {
                $crate::ring::testing::prove_verify::<$suite>()
            }

            #[test]
            fn ring_padding_check() {
                $crate::ring::testing::padding_check::<$suite>()
            }

            #[test]
            fn ring_accumulator_base_check() {
                $crate::ring::testing::accumulator_base_check::<$suite>()
            }
        };
    }

    pub trait RingSuiteExt: RingSuite
    where
        BaseField<Self>: ark_ff::PrimeField,
        CurveConfig<Self>: TECurveConfig + Clone,
        AffinePoint<Self>: TEMapping<CurveConfig<Self>>,
    {
        fn ring_context() -> &'static RingContext<Self>;
    }

    pub struct TestVector<S: RingSuite>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        pub pedersen: pedersen::testing::TestVector<S>,
        pub ring_pks: [AffinePoint<S>; TEST_RING_SIZE],
        pub ring_pks_com: RingCommitment<S>,
        pub ring_proof: RingProof<S>,
    }

    impl<S: RingSuite> core::fmt::Debug for TestVector<S>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TestVector")
                .field("pedersen", &self.pedersen)
                .field("ring_proof", &"...")
                .finish()
        }
    }

    impl<S: RingSuiteExt + std::fmt::Debug + 'static> common::TestVectorTrait for TestVector<S>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let pedersen = pedersen::testing::TestVector::new(comment, seed, alpha, salt, ad);

            let secret = Secret::<S>::from_scalar(pedersen.base.sk);
            let public = secret.public();

            let input = Input::<S>::from(pedersen.base.h);
            let output = Output::from(pedersen.base.gamma);

            let ring_ctx = <S as RingSuiteExt>::ring_context();

            use ark_std::rand::SeedableRng;
            let rng = &mut rand_chacha::ChaCha20Rng::from_seed([0x11; 32]);
            let prover_idx = 3;
            let mut ring_pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
            ring_pks[prover_idx] = public.0;

            let prover_key = ring_ctx.prover_key(&ring_pks);
            let prover = ring_ctx.prover(prover_key, prover_idx);
            let proof = secret.prove(input, output, ad, &prover);

            let verifier_key = ring_ctx.verifier_key(&ring_pks);
            let ring_pks_com = verifier_key.commitment();

            {
                // Just in case...
                let mut p = (Vec::new(), Vec::new());
                pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            // TODO: also dump the verifier pks commitment
            Self {
                pedersen,
                ring_pks: ring_pks.try_into().unwrap(),
                ring_pks_com,
                ring_proof: proof.ring_proof,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let pedersen = pedersen::testing::TestVector::from_map(map);

            let ring_pks = map.get::<[AffinePoint<S>; TEST_RING_SIZE]>("ring_pks");
            let ring_pks_com = map.get::<RingCommitment<S>>("ring_pks_com");
            let ring_proof = map.get::<RingProof<S>>("ring_proof");

            Self {
                pedersen,
                ring_pks,
                ring_pks_com,
                ring_proof,
            }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let mut map = self.pedersen.to_map();
            map.set("ring_pks", &self.ring_pks);
            map.set("ring_pks_com", &self.ring_pks_com);
            map.set("ring_proof", &self.ring_proof);
            map
        }

        fn run(&self) {
            self.pedersen.run();

            let input = Input::<S>::from(self.pedersen.base.h);
            let output = Output::from(self.pedersen.base.gamma);
            let secret = Secret::from_scalar(self.pedersen.base.sk);
            let public = secret.public();
            assert_eq!(public.0, self.pedersen.base.pk);

            let ring_ctx = <S as RingSuiteExt>::ring_context();

            let prover_idx = self.ring_pks.iter().position(|&pk| pk == public.0).unwrap();

            let prover_key = ring_ctx.prover_key(&self.ring_pks);
            let prover = ring_ctx.prover(prover_key, prover_idx);

            let verifier_key = ring_ctx.verifier_key(&self.ring_pks);
            let verifier = ring_ctx.verifier(verifier_key);

            let proof = secret.prove(input, output, &self.pedersen.base.ad, &prover);

            {
                // Check if Pedersen proof matches
                let mut p = (Vec::new(), Vec::new());
                self.pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            #[cfg(feature = "test-vectors")]
            {
                // Verify if the ring-proof matches. This check is performed only when
                // deterministic proof generation is required for test vectors.
                let mut p = (Vec::new(), Vec::new());
                self.ring_proof.serialize_compressed(&mut p.0).unwrap();
                proof.ring_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            assert!(
                Public::verify(input, output, &self.pedersen.base.ad, &proof, &verifier).is_ok()
            );
        }
    }
}
