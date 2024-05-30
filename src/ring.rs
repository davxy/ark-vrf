use crate::*;
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr};
use pedersen::{PedersenSuite, Proof as PedersenProof};

pub trait RingSuite: PedersenSuite {
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    const COMPLEMENT_POINT: AffinePoint<Self>;
}

pub type Curve<S> = <<S as Suite>::Affine as AffineRepr>::Config;

/// KZG Polynomial Commitment Scheme.
type Pcs<S> = fflonk::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG Setup Parameters.
///
/// Basically the powers of tau URS.
type PcsParams<S> = fflonk::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

type PairingScalarField<S> = <<S as RingSuite>::Pairing as ark_ec::pairing::Pairing>::ScalarField;

// pub type ProverKey<S> = ring_proof::ProverKey<PairingScalarField<S>, Pcs<S>, AffinePoint<S>>;
pub type ProverKey<S> = ring_proof::ProverKey<
    PairingScalarField<S>,
    Pcs<S>,
    ark_ec::short_weierstrass::Affine<Curve<S>>,
>;

pub type VerifierKey<S> = ring_proof::VerifierKey<PairingScalarField<S>, Pcs<S>>;

pub type Prover<S> = ring_proof::ring_prover::RingProver<PairingScalarField<S>, Pcs<S>, Curve<S>>;

pub type Verifier<S> =
    ring_proof::ring_verifier::RingVerifier<PairingScalarField<S>, Pcs<S>, Curve<S>>;

pub type RingProof<S> = ring_proof::RingProof<PairingScalarField<S>, Pcs<S>>;

pub type PiopParams<S> = ring_proof::PiopParams<PairingScalarField<S>, Curve<S>>;

pub trait Pairing<S: RingSuite>: ark_ec::pairing::Pairing<ScalarField = BaseField<S>> {}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
{
    pub pedersen_proof: PedersenProof<S>,
    pub ring_proof: RingProof<S>,
}

pub trait RingProver<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    Curve<S>: SWCurveConfig,
{
    /// Generate a proof for the given input/output and user additional data.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &Prover<S>,
    ) -> Proof<S>;
}

pub trait RingVerifier<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    Curve<S>: SWCurveConfig,
{
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &Verifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> RingProver<S> for Secret<S>
where
    BaseField<S>: ark_ff::PrimeField,
    Curve<S>: SWCurveConfig,
{
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &Prover<S>,
    ) -> Proof<S> {
        use crate::pedersen::PedersenProver;
        let (pedersen_proof, secret_blinding) =
            <Self as PedersenProver<S>>::prove(self, input, output, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Proof {
            pedersen_proof,
            ring_proof,
        }
    }
}

impl<S: RingSuite> RingVerifier<S> for Public<S>
where
    BaseField<S>: ark_ff::PrimeField,
    Curve<S>: SWCurveConfig,
    AffinePoint<S>: SwMap<Curve<S>>,
{
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &Verifier<S>,
    ) -> Result<(), Error> {
        use crate::pedersen::PedersenVerifier;
        <Self as PedersenVerifier<S>>::verify(input, output, ad, &sig.pedersen_proof)?;
        let key_commitment = sig.pedersen_proof.key_commitment().to_sw();
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
    Curve<S>: SWCurveConfig + Clone,
{
    pub pcs_params: PcsParams<S>,
    pub piop_params: PiopParams<S>,
    pub domain_size: usize,
}

impl<S: RingSuite> RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    Curve<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SwMap<Curve<S>>,
{
    pub fn from_seed(domain_size: usize, seed: [u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::new_random(domain_size, &mut rng)
    }

    pub fn new_random<R: ark_std::rand::RngCore>(domain_size: usize, rng: &mut R) -> Self {
        use fflonk::pcs::PCS;

        let pcs_params = <Pcs<S>>::setup(3 * domain_size, rng);
        let piop_params = make_piop_params::<S>(domain_size);
        Self {
            pcs_params,
            piop_params,
            domain_size,
        }
    }

    pub fn prover_key(&self, pks: Vec<AffinePoint<S>>) -> ProverKey<S> {
        let pks: Vec<_> = pks.into_iter().map(|p| p.to_sw()).collect();
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: Vec<AffinePoint<S>>) -> VerifierKey<S> {
        let pks: Vec<_> = pks.into_iter().map(|p| p.to_sw()).collect();
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    pub fn prover(&self, prover_key: ProverKey<S>, key_index: usize) -> Prover<S> {
        <Prover<S>>::init(
            prover_key,
            self.piop_params.clone(),
            key_index,
            merlin::Transcript::new(b"ring-vrf"),
        )
    }

    pub fn verifier(&self, verifier_key: VerifierKey<S>) -> Verifier<S> {
        <Verifier<S>>::init(
            verifier_key,
            self.piop_params.clone(),
            merlin::Transcript::new(b"ring-vrf"),
        )
    }
}

pub trait SwMap<C: SWCurveConfig> {
    fn to_sw(self) -> ark_ec::short_weierstrass::Affine<C>;
}

impl<C: SWCurveConfig> SwMap<C> for ark_ec::short_weierstrass::Affine<C> {
    fn to_sw(self) -> ark_ec::short_weierstrass::Affine<C> {
        self
    }
}

impl<C: utils::ark_next::MapConfig> SwMap<C> for ark_ec::twisted_edwards::Affine<C> {
    fn to_sw(self) -> ark_ec::short_weierstrass::Affine<C> {
        // println!("{:?}", self);
        let res = utils::ark_next::map_te_to_sw(&self).unwrap();
        // println!("{:?}", res);
        res
    }
}

fn make_piop_params<S: RingSuite>(domain_size: usize) -> PiopParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    Curve<S>: SWCurveConfig,
    AffinePoint<S>: SwMap<Curve<S>>,
{
    let domain = ring_proof::Domain::new(domain_size, true);
    PiopParams::<S>::setup(
        domain,
        S::BLINDING_BASE.to_sw(),
        S::COMPLEMENT_POINT.to_sw(),
    )
}
