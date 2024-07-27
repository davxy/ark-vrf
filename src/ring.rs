use crate::arkworks::te_sw_map::SWMapping;
use crate::*;
use ark_ec::short_weierstrass::SWCurveConfig;
use pedersen::{PedersenSuite, Proof as PedersenProof};

/// Ring suite.
pub trait RingSuite: PedersenSuite {
    /// Pairing type.
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    /// Complement point.
    const COMPLEMENT_POINT: AffinePoint<Self>;
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
pub type ProverKey<S> =
    ring_proof::ProverKey<BaseField<S>, Pcs<S>, ark_ec::short_weierstrass::Affine<CurveConfig<S>>>;

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
    CurveConfig<S>: SWCurveConfig,
{
    pub pedersen_proof: PedersenProof<S>,
    pub ring_proof: RingProof<S>,
}

pub trait Prover<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
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
    CurveConfig<S>: SWCurveConfig,
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
    CurveConfig<S>: SWCurveConfig,
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
    CurveConfig<S>: SWCurveConfig,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
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
        let key_commitment = sig.pedersen_proof.key_commitment().into_sw();
        if !verifier.verify_ring_proof(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RingContext<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
{
    pcs_params: PcsParams<S>,
    piop_params: PiopParams<S>,
}

#[inline(always)]
fn domain_size(ring_size: usize) -> usize {
    const RING_DOMAIN_OVERHEAD: usize = 257;
    1 << ark_std::log2(ring_size + RING_DOMAIN_OVERHEAD)
}

#[allow(private_bounds)]
impl<S: RingSuite> RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
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
        let domain_size = domain_size(ring_size);
        let pcs_params = Pcs::<S>::setup(3 * domain_size, rng);
        Self::from_srs(ring_size, pcs_params).expect("PCS params is correct")
    }

    pub fn from_srs(ring_size: usize, mut pcs_params: PcsParams<S>) -> Result<Self, Error> {
        let domain_size = domain_size(ring_size);
        if pcs_params.powers_in_g1.len() < 3 * domain_size + 1 || pcs_params.powers_in_g2.len() < 2
        {
            return Err(Error::InvalidData);
        }
        // Keep only the required powers of tau.
        pcs_params.powers_in_g1.truncate(3 * domain_size + 1);
        pcs_params.powers_in_g2.truncate(2);

        let piop_params = PiopParams::<S>::setup(
            ring_proof::Domain::new(domain_size, true),
            S::BLINDING_BASE.into_sw(),
            S::COMPLEMENT_POINT.into_sw(),
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
        let pks = SWMapping::to_sw_slice(&pks[..pks.len().min(self.max_ring_size())]);
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
            ring_proof::Transcript::new(b""),
        )
    }

    /// Construct a `VerifierKey` instance for the given ring.
    ///
    /// Note: if `pks.len() > self.max_ring_size()` the extra keys in the tail are ignored.
    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> VerifierKey<S> {
        let pks = SWMapping::to_sw_slice(&pks[..pks.len().min(self.max_ring_size())]);
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
            ring_proof::Transcript::new(b""),
        )
    }
}

impl<S: RingSuite> CanonicalSerialize for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
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
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
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
    CurveConfig<S>: SWCurveConfig + Clone,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.check()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::{pedersen, testing as common};

    const TEST_RING_SIZE: usize = 512;

    pub fn prove_verify<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: ark_ec::short_weierstrass::SWCurveConfig + Clone,
        AffinePoint<S>: utils::te_sw_map::SWMapping<CurveConfig<S>>,
    {
        let rng = &mut ark_std::test_rng();
        let ring_ctx = RingContext::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(common::TEST_SEED);
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

    pub fn check_complement_point<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: ark_ec::short_weierstrass::SWCurveConfig + Clone,
        AffinePoint<S>: utils::te_sw_map::SWMapping<CurveConfig<S>>,
    {
        use utils::te_sw_map::SWMapping;
        let pt = S::COMPLEMENT_POINT.into_sw();
        assert!(pt.is_on_curve());
        assert!(!pt.is_in_correct_subgroup_assuming_on_curve());
    }

    #[macro_export]
    macro_rules! ring_suite_tests {
        ($suite:ident, true) => {
            #[cfg(feature = "ring")]
            #[test]
            fn ring_prove_verify() {
                $crate::ring::testing::prove_verify::<$suite>()
            }

            #[cfg(feature = "ring")]
            #[test]
            fn check_complement_point() {
                $crate::ring::testing::check_complement_point::<$suite>()
            }
        };
        ($suite:ident, false) => {};
    }

    pub struct TestVector<S: RingSuite>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: SWCurveConfig + Clone,
        AffinePoint<S>: SWMapping<CurveConfig<S>>,
    {
        pub pedersen: pedersen::testing::TestVector<S>,
        pub ring: RingProof<S>,
    }

    impl<S: RingSuite> core::fmt::Debug for TestVector<S>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: SWCurveConfig + Clone,
        AffinePoint<S>: SWMapping<CurveConfig<S>>,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TestVector")
                .field("pedersen", &self.pedersen)
                .finish()
        }
    }

    impl<S: RingSuite + std::fmt::Debug> common::TestVectorTrait for TestVector<S>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: SWCurveConfig + Clone,
        AffinePoint<S>: SWMapping<CurveConfig<S>>,
    {
        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: Option<&[u8]>, ad: &[u8]) -> Self {
            use super::Prover;
            let pedersen = pedersen::testing::TestVector::new(comment, seed, alpha, salt, ad);

            let secret = Secret::<S>::from_scalar(pedersen.base.sk);
            let public = secret.public();

            let input = Input::<S>::from(pedersen.base.h);
            let output = Output::from(pedersen.base.gamma);

            // TODO: RingSuiteExt with a function to get a reference to the ring context ('static)
            // ring_ctx = RingSuiteExt::context()
            // The suite is then in charge of its construction
            // TODO: also dump the verifier pks commitmet

            use ark_std::rand::SeedableRng;
            let rng = &mut rand_chacha::ChaCha20Rng::from_seed([0x11; 32]);
            let ring_ctx = RingContext::<S>::from_rand(TEST_RING_SIZE, rng);
            let ring_size = ring_ctx.max_ring_size();

            let prover_idx = 3;
            let mut pks = common::random_vec::<AffinePoint<S>>(ring_size, Some(rng));
            pks[prover_idx] = public.0;

            let prover_key = ring_ctx.prover_key(&pks);
            let prover = ring_ctx.prover(prover_key, prover_idx);
            let proof = secret.prove(input, output, ad, &prover);

            {
                // Just in case...
                let mut p = (Vec::new(), Vec::new());
                pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            Self {
                pedersen,
                ring: proof.ring_proof,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let pedersen = pedersen::testing::TestVector::from_map(map);
            let ring_bytes = map.item_bytes("ring-proof");
            let ring_proof = RingProof::<S>::deserialize_compressed(&ring_bytes[..]).unwrap();
            Self {
                pedersen,
                ring: ring_proof,
            }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let mut map = self.pedersen.to_map();
            let mut ring_proof_raw = Vec::new();
            self.ring.serialize_compressed(&mut ring_proof_raw).unwrap();
            let ring_proof_hex = hex::encode(ring_proof_raw);
            map.0.insert("ring-proof".to_string(), ring_proof_hex);
            map
        }

        fn run(&self) {
            self.pedersen.run();

            let input = Input::<S>::from(self.pedersen.base.h);
            let output = Output::from(self.pedersen.base.gamma);
            let secret = Secret::from_scalar(self.pedersen.base.sk);
            let public = secret.public();

            use ark_std::rand::SeedableRng;
            let rng = &mut rand_chacha::ChaCha20Rng::from_seed([0x11; 32]);
            let ring_ctx = RingContext::<S>::from_rand(TEST_RING_SIZE, rng);
            let ring_size = ring_ctx.max_ring_size();

            let prover_idx = 3;
            let mut pks = common::random_vec::<AffinePoint<S>>(ring_size, Some(rng));
            pks[prover_idx] = public.0;

            let prover_key = ring_ctx.prover_key(&pks);
            let prover = ring_ctx.prover(prover_key, prover_idx);

            let verifier_key = ring_ctx.verifier_key(&pks);
            let verifier = ring_ctx.verifier(verifier_key);

            let proof = secret.prove(input, output, &self.pedersen.base.ad, &prover);

            {
                // Check if Pedersen proof matches
                let mut p = (Vec::new(), Vec::new());
                self.pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            // TODO
            // #[cfg(feature = "test-vectors")]
            {
                // Check if Ring proof matches
                let mut p = (Vec::new(), Vec::new());
                self.ring.serialize_compressed(&mut p.0).unwrap();
                proof.ring_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            assert!(
                Public::verify(input, output, &self.pedersen.base.ad, &proof, &verifier).is_ok()
            );
        }
    }
}
