//! # Ring VRF
//!
//! Implementation of a zero-knowledge VRF scheme providing signer anonymity within a set of
//! public keys, based on [BCHSV23](https://eprint.iacr.org/2023/002).
//!
//! This module is gated by the `ring` feature.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! // Ring setup
//! const RING_SIZE: usize = 100;
//! let prover_key_index = 3;
//!
//! // Create a ring of public keys
//! let mut ring = (0..RING_SIZE)
//!     .map(|i| Secret::from_seed(&i.to_le_bytes()).public().0)
//!     .collect::<Vec<_>>();
//! ring[prover_key_index] = public.0;
//!
//! // Initialize ring parameters
//! let params = RingProofParams::from_seed(RING_SIZE, b"example seed");
//!
//! // Proving
//! use ark_vrf::ring::Prover;
//! let prover_key = params.prover_key(&ring);
//! let prover = params.prover(prover_key, prover_key_index);
//! let proof = secret.prove(input, output, aux_data, &prover);
//!
//! // Verification
//! use ark_vrf::ring::Verifier;
//! let verifier_key = params.verifier_key(&ring);
//! let verifier = params.verifier(verifier_key);
//! let result = Public::verify(input, output, aux_data, &proof, &verifier);
//!
//! // Efficient verification with commitment
//! let ring_commitment = verifier_key.commitment();
//! let reconstructed_key = params.verifier_key_from_commitment(ring_commitment);
//! ```

use crate::*;
use ark_ec::{
    pairing::Pairing,
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_std::ops::Range;
use pedersen::{PedersenSuite, Proof as PedersenProof};
use utils::te_sw_map::TEMapping;
use w3f_ring_proof as ring_proof;

/// Magic spell for [RingSuite::ACCUMULATOR_BASE] generation in built-in implementations.
///
/// (en) *"The foundation of the accumulator which in the silence of time guards the hidden secret"*
pub const ACCUMULATOR_BASE_SEED: &[u8] =
    b"substratum accumulatoris quod in silentio temporis arcanum absconditum custodit";

/// Magic spell for [RingSuite::PADDING] generation in built-in implementations.
///
/// (en) *"A shadow that fills the void left by lost souls echoing among the darkness"*
pub const PADDING_SEED: &[u8] =
    b"umbra quae vacuum implet ab animabus perditis relictum inter tenebras resonans";

/// Ring suite.
///
/// This trait provides the cryptographic primitives needed for ring VRF signatures.
/// All required bounds are expressed directly on the associated type for better ergonomics.
pub trait RingSuite:
    PedersenSuite<
    Affine: AffineRepr<BaseField: ark_ff::PrimeField, Config: TECurveConfig + Clone>
                + TEMapping<<Self::Affine as AffineRepr>::Config>,
>
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

/// KZG Polinomial Commitment Scheme.
pub type Kzg<S> = ring_proof::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG commitment.
pub type PcsCommitment<S> =
    ring_proof::pcs::kzg::commitment::KzgCommitment<<S as RingSuite>::Pairing>;

/// KZG Polynomial Commitment Scheme parameters.
///
/// Basically powers of tau SRS.
pub type PcsParams<S> = ring_proof::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

/// Polynomial Interactive Oracle Proof (IOP) parameters.
///
/// Basically all the application specific parameters required to construct and
/// verify the ring proof.
pub type PiopParams<S> = ring_proof::PiopParams<BaseField<S>, CurveConfig<S>>;

/// Ring keys commitment.
pub type RingCommitment<S> = ring_proof::FixedColumnsCommitted<BaseField<S>, PcsCommitment<S>>;

/// Ring prover key.
pub type RingProverKey<S> = ring_proof::ProverKey<BaseField<S>, Kzg<S>, TEAffine<CurveConfig<S>>>;

/// Ring verifier key.
pub type RingVerifierKey<S> = ring_proof::VerifierKey<BaseField<S>, Kzg<S>>;

/// Ring prover.
pub type RingProver<S> = ring_proof::ring_prover::RingProver<BaseField<S>, Kzg<S>, CurveConfig<S>>;

/// Ring verifier.
pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, Kzg<S>, CurveConfig<S>>;

/// Ring proof batch verifier (KZG-based).
pub type RingBatchVerifier<S> = ring_proof::ring_verifier::KzgBatchVerifier<
    <S as RingSuite>::Pairing,
    CurveConfig<S>,
    ring_proof::ArkTranscript,
>;

/// Raw ring proof.
///
/// This is the primitive ring proof used in conjunction with Pedersen proof to
/// construct the actual ring vrf proof [`Proof`].
pub type RingBareProof<S> = ring_proof::RingProof<BaseField<S>, Kzg<S>>;

/// Ring VRF proof.
///
/// Two-part zero-knowledge proof with signer anonymity:
/// - `pedersen_proof`: Key commitment and VRF correctness proof
/// - `ring_proof`: Membership proof binding the commitment to the ring
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: RingSuite> {
    /// Pedersen VRF proof (key commitment and VRF correctness).
    pub pedersen_proof: PedersenProof<S>,
    /// Ring membership proof binding the key commitment to the ring.
    pub ring_proof: RingBareProof<S>,
}

/// Trait for types that can generate Ring VRF proofs.
///
/// Implementors can create anonymous proofs that a VRF output
/// is correctly derived using a secret key from a ring of public keys.
pub trait Prover<S: RingSuite> {
    /// Generate a proof for the given input/output and additional data.
    ///
    /// Creates a zero-knowledge proof that:
    /// 1. The prover knows a secret key for one of the ring's public keys
    /// 2. That secret key was used to compute the VRF output
    ///
    /// * `input` - VRF input point
    /// * `output` - VRF output point
    /// * `ad` - Additional data to bind to the proof
    /// * `prover` - Ring prover instance for the specific ring position
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &RingProver<S>,
    ) -> Proof<S>;
}

/// Trait for entities that can verify Ring VRF proofs.
///
/// Implementors can verify anonymous proofs that a VRF output
/// was derived using a secret key from a ring of public keys.
pub trait Verifier<S: RingSuite> {
    /// Verify a proof for the given input/output and additional data.
    ///
    /// Verifies that:
    /// 1. The proof was created by a member of the ring
    /// 2. The VRF output is correct for the given input
    /// 3. The additional data matches what was used during proving
    ///
    /// * `input` - VRF input point
    /// * `output` - Claimed VRF output point
    /// * `ad` - Additional data bound to the proof
    /// * `sig` - The proof to verify
    /// * `verifier` - Ring verifier instance for the specific ring
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::VerificationFailure)` otherwise.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> Prover<S> for Secret<S> {
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

impl<S: RingSuite> Verifier<S> for Public<S> {
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error> {
        use pedersen::Verifier as PedersenVerifier;
        <Self as PedersenVerifier<S>>::verify(input, output, ad, &proof.pedersen_proof)?;
        let key_commitment = proof.pedersen_proof.key_commitment().into_te();
        if !verifier.verify(proof.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

/// Ring proof parameters.
///
/// Contains the cryptographic parameters needed for ring proof generation and verification:
/// - `pcs`: Polynomial Commitment Scheme parameters (KZG setup)
/// - `piop`: Polynomial Interactive Oracle Proof parameters
#[derive(Clone)]
pub struct RingProofParams<S: RingSuite> {
    /// PCS parameters.
    pub pcs: PcsParams<S>,
    /// PIOP parameters.
    pub piop: PiopParams<S>,
}

pub(crate) fn piop_params<S: RingSuite>(domain_size: usize) -> PiopParams<S> {
    PiopParams::<S>::setup(
        ring_proof::Domain::new(domain_size, true),
        S::BLINDING_BASE.into_te(),
        S::ACCUMULATOR_BASE.into_te(),
        S::PADDING.into_te(),
    )
}

impl<S: RingSuite> RingProofParams<S> {
    /// Construct deterministic ring proof params for the given ring size.
    ///
    /// Creates parameters using a deterministic `ChaCha20Rng` seeded with `seed`.
    pub fn from_seed(ring_size: usize, seed: [u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::from_rand(ring_size, &mut rng)
    }

    /// Construct random ring proof params for the given ring size.
    ///
    /// Generates a new KZG setup with sufficient degree to support the specified ring size.
    pub fn from_rand(ring_size: usize, rng: &mut impl ark_std::rand::RngCore) -> Self {
        use ring_proof::pcs::PCS;
        let max_degree = pcs_domain_size::<S>(ring_size) - 1;
        let pcs_params = Kzg::<S>::setup(max_degree, rng);
        Self::from_pcs_params(ring_size, pcs_params).expect("PCS params is correct")
    }

    /// Construct ring proof params from existing KZG setup.
    ///
    /// Creates parameters using an existing KZG setup, truncating if larger than needed
    /// or returning an error if the setup is insufficient for the specified ring size.
    ///
    /// * `ring_size` - Maximum number of keys in the ring
    /// * `pcs_params` - KZG setup parameters
    pub fn from_pcs_params(ring_size: usize, mut pcs_params: PcsParams<S>) -> Result<Self, Error> {
        let pcs_domain_size = pcs_domain_size::<S>(ring_size);
        if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
            return Err(Error::InvalidData);
        }
        // Keep only the required powers of tau
        pcs_params.powers_in_g1.truncate(pcs_domain_size);
        pcs_params.powers_in_g2.truncate(2);
        let piop_domain_size = piop_domain_size::<S>(ring_size);
        Ok(Self {
            pcs: pcs_params,
            piop: piop_params::<S>(piop_domain_size),
        })
    }

    /// The max ring size these parameters are able to handle.
    #[inline(always)]
    pub fn max_ring_size(&self) -> usize {
        self.piop.keyset_part_size
    }

    /// Create a prover key for the given ring of public keys.
    ///
    /// Indexes the ring and prepares the cryptographic material needed for proving.
    /// If the ring exceeds the maximum supported size, excess keys are ignored.
    ///
    /// * `pks` - Array of public keys forming the ring
    pub fn prover_key(&self, pks: &[AffinePoint<S>]) -> RingProverKey<S> {
        let pks = TEMapping::to_te_slice(&pks[..pks.len().min(self.max_ring_size())]);
        ring_proof::index(&self.pcs, &self.piop, &pks).0
    }

    /// Create a prover instance for a specific position in the ring.
    ///
    /// * `prover_key` - Ring prover key created with `prover_key()`
    /// * `key_index` - Position of the prover's public key in the original ring
    pub fn prover(&self, prover_key: RingProverKey<S>, key_index: usize) -> RingProver<S> {
        RingProver::<S>::init(
            prover_key,
            self.piop.clone(),
            key_index,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Create a verifier key for the given ring of public keys.
    ///
    /// Indexes the ring and prepares the cryptographic material needed for verification.
    /// If the ring exceeds the maximum supported size, excess keys are ignored.
    ///
    /// * `pks` - Array of public keys forming the ring
    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> RingVerifierKey<S> {
        let pks = TEMapping::to_te_slice(&pks[..pks.len().min(self.max_ring_size())]);
        ring_proof::index(&self.pcs, &self.piop, &pks).1
    }

    /// Create a verifier key from a precomputed ring commitment.
    ///
    /// Allows efficient reconstruction of a verifier key without needing the full ring.
    /// The commitment can be obtained from an existing verifier key via `commitment()`.
    ///
    /// * `commitment` - Precomputed commitment to the ring of public keys
    pub fn verifier_key_from_commitment(
        &self,
        commitment: RingCommitment<S>,
    ) -> RingVerifierKey<S> {
        use ring_proof::pcs::PcsParams;
        RingVerifierKey::<S>::from_commitment_and_kzg_vk(commitment, self.pcs.raw_vk())
    }

    /// Clone a verifier key by reconstructing it from its commitment.
    ///
    /// Workaround for upstream `RingVerifierKey` not implementing `Clone`.
    pub fn clone_verifier_key(&self, verifier_key: &RingVerifierKey<S>) -> RingVerifierKey<S> {
        self.verifier_key_from_commitment(verifier_key.commitment())
    }

    /// Create a builder for incremental construction of the verifier key.
    ///
    /// Returns a builder and associated PCS parameters that can be used to
    /// construct a verifier key by adding public keys in batches.
    pub fn verifier_key_builder(&self) -> (VerifierKeyBuilder<S>, RingBuilderPcsParams<S>) {
        type RingBuilderKey<S> =
            ring_proof::ring::RingBuilderKey<BaseField<S>, <S as RingSuite>::Pairing>;
        let piop_domain_size = piop_domain_size::<S>(self.piop.keyset_part_size);
        let builder_key = RingBuilderKey::<S>::from_srs(&self.pcs, piop_domain_size);
        let builder_pcs_params = RingBuilderPcsParams(builder_key.lis_in_g1);
        let builder = VerifierKeyBuilder::new(self, &builder_pcs_params);
        (builder, builder_pcs_params)
    }

    /// Create a verifier instance from a verifier key.
    ///
    /// * `verifier_key` - Ring verifier key created with `verifier_key()`
    pub fn verifier(&self, verifier_key: RingVerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop.clone(),
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Create a verifier instance without requiring the full parameters.
    ///
    /// Creates a verifier using only the verifier key and ring size, computing
    /// necessary parameters on-the-fly. This is more memory efficient but slightly
    /// less computationally efficient than using the full parameters.
    ///
    /// * `verifier_key` - Ring verifier key
    /// * `ring_size` - Size of the ring used to create the verifier key
    pub fn verifier_no_context(
        verifier_key: RingVerifierKey<S>,
        ring_size: usize,
    ) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            piop_params::<S>(piop_domain_size::<S>(ring_size)),
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Get the padding point.
    ///
    /// This is a point of unknown dlog that can be used in place of any key during
    /// ring construciton.
    #[inline(always)]
    pub const fn padding_point() -> AffinePoint<S> {
        S::PADDING
    }
}

impl<S: RingSuite> CanonicalSerialize for RingProofParams<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.pcs.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.pcs.serialized_size(compress)
    }
}

impl<S: RingSuite> CanonicalDeserialize for RingProofParams<S> {
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
        let piop_domain_size = piop_domain_size_from_pcs_domain_size(pcs_params.powers_in_g1.len());
        Ok(Self {
            pcs: pcs_params,
            piop: piop_params::<S>(piop_domain_size),
        })
    }
}

impl<S: RingSuite> ark_serialize::Valid for RingProofParams<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pcs.check()
    }
}

/// Information required for incremental ring construction.
///
/// Basically the SRS in Lagrangian form.
/// Can be constructed via the `PcsParams::ck_with_lagrangian()` method.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingBuilderPcsParams<S: RingSuite>(pub Vec<G1Affine<S>>);

// Under construction ring commitment.
type PartialRingCommitment<S> =
    ring_proof::ring::Ring<BaseField<S>, <S as RingSuite>::Pairing, CurveConfig<S>>;

type RawVerifierKey<S> = <PcsParams<S> as ring_proof::pcs::PcsParams>::RVK;

/// Builder for incremental construction of ring verifier keys.
///
/// Allows constructing a verifier key by adding public keys in batches,
/// which is useful for large rings or memory-constrained environments.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierKeyBuilder<S: RingSuite> {
    partial: PartialRingCommitment<S>,
    raw_vk: RawVerifierKey<S>,
}

/// Pairing G1 affine point type.
pub type G1Affine<S> = <<S as RingSuite>::Pairing as Pairing>::G1Affine;
/// Pairing G2 affine point type.
pub type G2Affine<S> = <<S as RingSuite>::Pairing as Pairing>::G2Affine;

/// Trait for accessing Structured Reference String entries in Lagrangian basis.
///
/// Provides access to precomputed SRS elements needed for efficient ring operations.
pub trait SrsLookup<S: RingSuite> {
    /// Look up a range of SRS elements. Returns `None` if the range is out of bounds.
    fn lookup(&self, range: Range<usize>) -> Option<Vec<G1Affine<S>>>;
}

impl<S: RingSuite, F> SrsLookup<S> for F
where
    F: Fn(Range<usize>) -> Option<Vec<G1Affine<S>>>,
{
    fn lookup(&self, range: Range<usize>) -> Option<Vec<G1Affine<S>>> {
        self(range)
    }
}

impl<S: RingSuite> SrsLookup<S> for &RingBuilderPcsParams<S> {
    fn lookup(&self, range: Range<usize>) -> Option<Vec<G1Affine<S>>> {
        if range.end > self.0.len() {
            return None;
        }
        Some(self.0[range].to_vec())
    }
}

impl<S: RingSuite> VerifierKeyBuilder<S> {
    /// Create a new empty ring verifier key builder.
    ///
    /// * `params` - Ring proof parameters
    /// * `lookup` - SRS lookup implementation for accessing precomputed values
    pub fn new(params: &RingProofParams<S>, lookup: impl SrsLookup<S>) -> Self {
        use ring_proof::pcs::PcsParams;
        let lookup = |range: Range<usize>| lookup.lookup(range).ok_or(());
        let raw_vk = params.pcs.raw_vk();
        let partial =
            PartialRingCommitment::<S>::empty(&params.piop, lookup, raw_vk.g1.into_group());
        VerifierKeyBuilder { partial, raw_vk }
    }

    /// Get the number of remaining slots available in the ring.
    #[inline(always)]
    pub fn free_slots(&self) -> usize {
        self.partial.max_keys - self.partial.curr_keys
    }

    /// Add public keys to the ring being built.
    ///
    /// * `pks` - Public keys to add to the ring
    /// * `lookup` - SRS lookup implementation for accessing precomputed values
    ///
    /// Returns `Ok(())` if keys were added successfully, or `Err(available_slots)`
    /// if there's not enough space. Returns `Err(usize::MAX)` if SRS lookup fails.
    pub fn append(
        &mut self,
        pks: &[AffinePoint<S>],
        lookup: impl SrsLookup<S>,
    ) -> Result<(), usize> {
        let avail_slots = self.free_slots();
        if avail_slots < pks.len() {
            return Err(avail_slots);
        }
        // Currently `ring-proof` backend panics if lookup fails.
        // This workaround makes lookup failures a bit less harsh.
        let segment = lookup
            .lookup(self.partial.curr_keys..self.partial.curr_keys + pks.len())
            .ok_or(usize::MAX)?;
        let lookup = |range: Range<usize>| {
            debug_assert_eq!(segment.len(), range.len());
            Ok(segment.clone())
        };
        let pks = TEMapping::to_te_slice(pks);
        self.partial.append(&pks, lookup);
        Ok(())
    }

    /// Complete the building process and create the verifier key.
    pub fn finalize(self) -> RingVerifierKey<S> {
        RingVerifierKey::<S>::from_ring_and_kzg_vk(&self.partial, self.raw_vk)
    }
}

type RingPreparedBatchItem<S> =
    ring_proof::ring_verifier::PreparedBatchItem<<S as RingSuite>::Pairing, CurveConfig<S>>;

/// Pre-processed data for a single ring proof awaiting batch verification.
pub struct BatchItem<S: RingSuite> {
    ring: RingPreparedBatchItem<S>,
    pedersen: pedersen::BatchItem<S>,
}

/// Batch verifier for ring VRF proofs.
///
/// Collects multiple ring proofs and verifies them together, amortizing the
/// cost of pairing checks and multi-scalar multiplications.
pub struct BatchVerifier<S: RingSuite> {
    ring_batch: RingBatchVerifier<S>,
    pedersen_batch: pedersen::BatchVerifier<S>,
}

impl<S: RingSuite> BatchVerifier<S> {
    /// Create a new batch verifier from a ring verifier instance.
    pub fn new(ring_verifier: RingVerifier<S>) -> Self {
        Self {
            ring_batch: ring_verifier.kzg_batch_verifier(),
            pedersen_batch: pedersen::BatchVerifier::new(),
        }
    }

    /// Prepare a proof for deferred batch verification.
    ///
    /// Performs the cheap per-proof work (hashing, transcript setup) without
    /// the expensive pairing and MSM checks.
    pub fn prepare(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> BatchItem<S> {
        let pedersen = pedersen::BatchVerifier::prepare(input, output, ad, &proof.pedersen_proof);
        let key_commitment = proof.pedersen_proof.key_commitment().into_te();
        let ring = self
            .ring_batch
            .prepare(proof.ring_proof.clone(), key_commitment);
        BatchItem { ring, pedersen }
    }

    /// Push a previously prepared item into the batch.
    pub fn push_prepared(&mut self, item: BatchItem<S>) {
        self.pedersen_batch.push_prepared(item.pedersen);
        self.ring_batch.push_prepared(item.ring);
    }

    /// Prepare and push a proof in one step.
    pub fn push(
        &mut self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) {
        let prepared = self.prepare(input, output, ad, proof);
        self.push_prepared(prepared);
    }

    /// Verify all collected proofs in a single batch.
    ///
    /// Checks both the Pedersen proofs (via MSM) and the ring proofs (via pairing).
    /// Returns `Ok(())` if all proofs verify, `Err(VerificationFailure)` otherwise.
    pub fn verify(&self) -> Result<(), Error> {
        self.pedersen_batch.verify()?;
        self.ring_batch
            .verify()
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

/// Type aliases for the given ring suite.
#[macro_export]
macro_rules! ring_suite_types {
    ($suite:ident) => {
        #[allow(dead_code)]
        pub type PcsParams = $crate::ring::PcsParams<$suite>;
        #[allow(dead_code)]
        pub type PiopParams = $crate::ring::PiopParams<$suite>;
        #[allow(dead_code)]
        pub type RingProofParams = $crate::ring::RingProofParams<$suite>;
        #[allow(dead_code)]
        pub type RingProverKey = $crate::ring::RingProverKey<$suite>;
        #[allow(dead_code)]
        pub type RingVerifierKey = $crate::ring::RingVerifierKey<$suite>;
        #[allow(dead_code)]
        pub type RingCommitment = $crate::ring::RingCommitment<$suite>;
        #[allow(dead_code)]
        pub type RingProver = $crate::ring::RingProver<$suite>;
        #[allow(dead_code)]
        pub type RingVerifier = $crate::ring::RingVerifier<$suite>;
        #[allow(dead_code)]
        pub type RingProof = $crate::ring::Proof<$suite>;
        #[allow(dead_code)]
        pub type RingVerifierKeyBuilder = $crate::ring::VerifierKeyBuilder<$suite>;
        #[allow(dead_code)]
        pub type RingBatchItem = $crate::ring::BatchItem<$suite>;
        #[allow(dead_code)]
        pub type RingBatchVerifier = $crate::ring::BatchVerifier<$suite>;
    };
}

/// Domain size conversion utilities
///
/// The ring proof system operates with three related size parameters:
///
/// 1. `min_ring_size`: Number of keys that the ring should accomodate (user-facing parameter)
/// 2. `max_ring_size`: Max number of keys that the ring can accomodate
/// 3. `piop_domain_size`: Size of the PIOP (Polynomial IOP) domain
/// 4. `pcs_domain_size`: Size of the PCS (Polynomial Commitment Scheme) domain
///
/// Relationships:
///   piop_domain_size = (ring_size + PIOP_OVERHEAD).next_power_of_two()
///   pcs_domain_size  = 3 * piop_domain_size + 1
///   max_ring_size    = piop_domain_size - PIOP_OVERHEAD
///
/// where PIOP_OVERHEAD = 4 + MODULUS_BIT_SIZE accounts for:
///   - 3 points for zero-knowledge blinding
///   - 1 extra point used internally by the PIOP
///   - MODULUS_BIT_SIZE bits for blinding factor
///
/// Note: Multiple ring sizes map to the same domain sizes due to power-of-2 rounding.
/// For example, ring sizes 1-254 (with 254-bit scalar) all map to piop_domain_size=512
/// and pcs_domain_size=1537.
pub mod dom_utils {
    use super::*;

    /// Returns the actual ring capacity for a given minimum size requirement.
    ///
    /// Because domain sizes round up to powers of 2, allocating for `min_ring_size`
    /// keys typically provides capacity for more. This function returns that actual
    /// capacity: the largest ring size that uses the same domain as `min_ring_size`.
    ///
    /// Always returns a value `>= min_ring_size`.
    pub const fn max_ring_size<S: Suite>(min_ring_size: usize) -> usize {
        max_ring_size_from_piop_domain_size::<S>(piop_domain_size::<S>(min_ring_size))
    }

    /// PIOP overhead: accounts for 3 ZK blinding points + 1 internal point + scalar field bits.
    pub const fn piop_overhead<S: Suite>() -> usize {
        4 + ScalarField::<S>::MODULUS_BIT_SIZE as usize
    }

    /// PIOP domain size required to support the given ring size.
    ///
    /// Returns the smallest power of 2 that can accommodate `min_ring_capactity` members.
    /// This is the domain size used for polynomial operations in the ring proof and
    /// already accounts for the PIOP overhead.
    pub const fn piop_domain_size<S: Suite>(min_ring_capacity: usize) -> usize {
        (min_ring_capacity + piop_overhead::<S>()).next_power_of_two()
    }

    /// Maximum ring size supported by a given PIOP domain size.
    ///
    /// Returns the largest ring that fits in the domain.
    pub const fn max_ring_size_from_piop_domain_size<S: Suite>(piop_domain_size: usize) -> usize {
        piop_domain_size - piop_overhead::<S>()
    }

    /// PCS domain size required to support the given ring size.
    ///
    /// Returns `3 * piop_domain_size + 1`. This is the number of G1 elements required
    /// in the SRS (powers of tau) for the prover. The verifier only needs the PIOP domain size.
    pub const fn pcs_domain_size<S: Suite>(min_ring_size: usize) -> usize {
        pcs_domain_size_from_piop_domain_size(piop_domain_size::<S>(min_ring_size))
    }

    /// PCS domain size for a given PIOP domain size.
    ///
    /// Returns `3 * piop_domain_size + 1`.
    pub const fn pcs_domain_size_from_piop_domain_size(piop_domain_size: usize) -> usize {
        3 * piop_domain_size + 1
    }

    /// PIOP domain size extracted from a PCS domain size.
    ///
    /// Recovers the PIOP domain size from a PCS domain size. The ilog2 ensures we get
    /// a valid power of 2 even if the input wasn't properly constructed.
    pub const fn piop_domain_size_from_pcs_domain_size(pcs_domain_size: usize) -> usize {
        1 << ((pcs_domain_size - 1) / 3).ilog2()
    }

    /// Maximum ring size supported by a given PCS domain size.
    ///
    /// Composes `piop_domain_size_from_pcs_domain_size` and `max_ring_size_from_piop_domain_size`.
    pub const fn max_ring_size_from_pcs_domain_size<S: Suite>(pcs_domain_size: usize) -> usize {
        let piop_domain_size = piop_domain_size_from_pcs_domain_size(pcs_domain_size);
        max_ring_size_from_piop_domain_size::<S>(piop_domain_size)
    }
}
use dom_utils::*;

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::pedersen;
    use crate::testing::{self as common, CheckPoint, TEST_SEED};
    use ark_ec::{
        short_weierstrass::{Affine as SWAffine, SWCurveConfig},
        twisted_edwards::{Affine as TEAffine, TECurveConfig},
    };

    pub const TEST_RING_SIZE: usize = 8;

    const MAX_AD_LEN: usize = 100;

    fn find_complement_point<C: SWCurveConfig>() -> SWAffine<C> {
        use ark_ff::{One, Zero};
        assert!(!C::cofactor_is_one());
        let mut x = C::BaseField::zero();
        loop {
            if let Some(p) = SWAffine::get_point_from_x_unchecked(x, false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
            {
                return p;
            }
            x += C::BaseField::one();
        }
    }

    pub trait FindAccumulatorBase<S: Suite>: Sized {
        const IN_PRIME_ORDER_SUBGROUP: bool;
        fn find_accumulator_base(data: &[u8]) -> Option<Self>;
    }

    impl<S, C> FindAccumulatorBase<S> for SWAffine<C>
    where
        C: SWCurveConfig,
        S: Suite<Affine = Self>,
    {
        const IN_PRIME_ORDER_SUBGROUP: bool = false;

        fn find_accumulator_base(data: &[u8]) -> Option<Self> {
            let p = S::data_to_point(data)?;
            let c = find_complement_point();
            let res = (p + c).into_affine();
            debug_assert!(!res.is_in_correct_subgroup_assuming_on_curve());
            Some(res)
        }
    }

    impl<S, C> FindAccumulatorBase<S> for TEAffine<C>
    where
        C: TECurveConfig,
        S: Suite<Affine = Self>,
    {
        const IN_PRIME_ORDER_SUBGROUP: bool = true;

        fn find_accumulator_base(data: &[u8]) -> Option<Self> {
            let res = S::data_to_point(data)?;
            debug_assert!(res.is_in_correct_subgroup_assuming_on_curve());
            Some(res)
        }
    }

    struct BatchItem<S: RingSuite> {
        input: Input<S>,
        output: Output<S>,
        ad: Vec<u8>,
        proof: Proof<S>,
    }

    impl<S: RingSuite> BatchItem<S> {
        fn new(
            secret: &Secret<S>,
            prover: &RingProver<S>,
            rng: &mut dyn ark_std::rand::RngCore,
        ) -> Self {
            let input = Input::from(common::random_val(Some(rng)));
            let output = secret.output(input);
            let ad_len = common::random_val::<usize>(Some(rng)) % (MAX_AD_LEN + 1);
            let ad = common::random_vec(ad_len, Some(rng));
            let proof = secret.prove(input, output, &ad, prover);
            Self {
                input,
                output,
                ad,
                proof,
            }
        }
    }

    #[allow(unused)]
    pub fn prove_verify<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let params = RingProofParams::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = public.0;

        let prover_key = params.prover_key(&pks);
        let prover = params.prover(prover_key, prover_idx);

        let item = BatchItem::<S>::new(&secret, &prover, rng);

        let verifier_key = params.verifier_key(&pks);
        let verifier = params.verifier(verifier_key);
        let result = Public::verify(item.input, item.output, &item.ad, &item.proof, &verifier);
        assert!(result.is_ok());
    }

    #[allow(unused)]
    pub fn prove_verify_batch<S: RingSuite>() {
        use rayon::prelude::*;

        const BATCH_SIZE: usize = 3 * TEST_RING_SIZE;

        let rng = &mut ark_std::test_rng();
        let params = RingProofParams::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = public.0;

        let prover_key = params.prover_key(&pks);
        let prover = params.prover(prover_key, prover_idx);

        // Generate proofs in parallel
        let batch: Vec<_> = (0..BATCH_SIZE)
            .into_par_iter()
            .map_init(ark_std::test_rng, |rng, _| {
                BatchItem::<S>::new(&secret, &prover, rng)
            })
            .collect();

        let verifier_key = params.verifier_key(&pks);
        let verifier = params.verifier(verifier_key);

        // Batch verify all proofs
        let mut batch_verifier = BatchVerifier::<S>::new(verifier);
        let res = batch_verifier.verify();
        assert!(res.is_ok());

        // Prove incrementally constructed batches
        for item in batch.iter() {
            batch_verifier.push(item.input, item.output, &item.ad, &item.proof);
            let res = batch_verifier.verify();
            assert!(res.is_ok());
        }

        println!("Batch size = {BATCH_SIZE}");

        println!("============================================================");

        let verifier_key = params.verifier_key(&pks);
        let verifier = params.verifier(verifier_key);
        let mut batch_verifier = BatchVerifier::<S>::new(verifier);
        let start = std::time::Instant::now();
        common::timed("Proofs push", || {
            for item in batch.iter() {
                batch_verifier.push(item.input, item.output, &item.ad, &item.proof);
            }
        });
        common::timed("Unprepared batch verification", || batch_verifier.verify());
        println!("Total time: {:?}", start.elapsed());

        println!("============================================================");

        let verifier_key = params.verifier_key(&pks);
        let verifier = params.verifier(verifier_key);
        let mut batch_verifier = BatchVerifier::<S>::new(verifier);
        let start = std::time::Instant::now();
        let prepared = common::timed("Proofs prepare", || {
            batch
                .par_iter()
                .map(|item| batch_verifier.prepare(item.input, item.output, &item.ad, &item.proof))
                .collect::<Vec<_>>()
        });
        common::timed("Proofs push prepared", || {
            prepared
                .into_iter()
                .for_each(|p| batch_verifier.push_prepared(p))
        });
        common::timed("Prepared batch verification", || batch_verifier.verify());
        println!("Total time: {:?}", start.elapsed());
    }

    #[allow(unused)]
    pub fn padding_check<S: RingSuite>()
    where
        AffinePoint<S>: CheckPoint,
    {
        // Check that point has been computed using the magic spell.
        assert_eq!(S::PADDING, S::data_to_point(PADDING_SEED).unwrap());

        // Check that the point is on curve.
        assert!(S::PADDING.check(true).is_ok());
    }

    #[allow(unused)]
    pub fn accumulator_base_check<S: RingSuite>()
    where
        AffinePoint<S>: FindAccumulatorBase<S> + CheckPoint,
    {
        // Check that point has been computed using the magic spell.
        assert_eq!(
            S::ACCUMULATOR_BASE,
            AffinePoint::<S>::find_accumulator_base(ACCUMULATOR_BASE_SEED).unwrap()
        );

        // SW form requires accumulator seed to be outside prime order subgroup.
        // TE form requires accumulator seed to be in prime order subgroup.
        let in_prime_subgroup = <AffinePoint<S> as FindAccumulatorBase<S>>::IN_PRIME_ORDER_SUBGROUP;
        assert!(S::ACCUMULATOR_BASE.check(in_prime_subgroup).is_ok());
    }

    #[allow(unused)]
    pub fn verifier_key_builder<S: RingSuite>() {
        use crate::testing::{random_val, random_vec};

        let rng = &mut ark_std::test_rng();
        let params = RingProofParams::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(common::random_val(Some(rng)));
        let output = secret.output(input);

        let ring_size = params.max_ring_size();
        let prover_idx = random_val::<usize>(Some(rng)) % ring_size;
        let mut pks = random_vec::<AffinePoint<S>>(ring_size, Some(rng));
        pks[prover_idx] = public.0;

        let prover_key = params.prover_key(&pks);
        let prover = params.prover(prover_key, prover_idx);
        let proof = secret.prove(input, output, b"foo", &prover);

        // Incremental ring verifier key construction
        let (mut vk_builder, lookup) = params.verifier_key_builder();
        assert_eq!(vk_builder.free_slots(), pks.len());

        let extra_pk = random_val::<AffinePoint<S>>(Some(rng));
        assert_eq!(
            vk_builder.append(&[extra_pk], |_| None).unwrap_err(),
            usize::MAX
        );

        while !pks.is_empty() {
            let chunk_len = 1 + random_val::<usize>(Some(rng)) % 5;
            let chunk = pks.drain(..pks.len().min(chunk_len)).collect::<Vec<_>>();
            vk_builder.append(&chunk[..], &lookup).unwrap();
            assert_eq!(vk_builder.free_slots(), pks.len());
        }
        // No more space left
        let extra_pk = random_val::<AffinePoint<S>>(Some(rng));
        assert_eq!(vk_builder.append(&[extra_pk], &lookup).unwrap_err(), 0);
        let verifier_key = vk_builder.finalize();
        let verifier = params.verifier(verifier_key);
        let result = Public::verify(input, output, b"foo", &proof, &verifier);
        assert!(result.is_ok());
    }

    pub fn domain_size_conversions<S: RingSuite>() {
        let overhead = piop_overhead::<S>();

        for ring_size in [1, 10, 200, 300, 500, 1000, 2000, 10000] {
            let piop_dom_size = piop_domain_size::<S>(ring_size);
            let pcs_dom_size = pcs_domain_size::<S>(ring_size);
            let max_ring_size = max_ring_size_from_piop_domain_size::<S>(piop_dom_size);

            assert!(piop_dom_size.is_power_of_two());
            assert_eq!(pcs_dom_size, 3 * piop_dom_size + 1);

            // piop_domain_size must fit ring_size + overhead
            assert!(piop_dom_size >= ring_size + overhead);
            // piop_domain_size is the smallest power of 2 that fits
            assert!(piop_dom_size / 2 < ring_size + overhead);
            // piop_dom_size is sufficient for max_ring_size
            assert_eq!(piop_dom_size, piop_domain_size::<S>(max_ring_size));
            // ring_size <= max_ring_size for the computed domain
            assert!(ring_size <= max_ring_size);

            // max_ring_size() helper equivalence
            assert_eq!(dom_utils::max_ring_size::<S>(ring_size), max_ring_size);
            // max_ring_size() is idempotent
            assert_eq!(dom_utils::max_ring_size::<S>(max_ring_size), max_ring_size);

            // Round-trip
            let piop_dom_rt = piop_domain_size_from_pcs_domain_size(pcs_dom_size);
            assert_eq!(piop_dom_size, piop_dom_rt);
            let pcs_dom_rt = pcs_domain_size_from_piop_domain_size(piop_dom_rt);
            assert_eq!(pcs_dom_size, pcs_dom_rt);

            let max_ring_from_pcs = max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size);
            assert_eq!(max_ring_size, max_ring_from_pcs);

            // max_ring + 1 should require a larger piop domain
            let next_piop = piop_domain_size::<S>(max_ring_size + 1);
            assert!(next_piop > piop_dom_size,);
            assert!(next_piop.is_power_of_two());
        }

        // Test inverse with arbitrary PCS values (not necessarily properly constructed)
        // The inverse function should recover the largest valid piop that fits
        for pcs_dom_size in [1 << 11, 1 << 12, 1 << 14, 1 << 16] {
            let piop_dom = piop_domain_size_from_pcs_domain_size(pcs_dom_size);
            let max_ring = max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size);

            assert!(piop_dom.is_power_of_two());
            // piop should satisfy: 3 * piop + 1 <= pcs
            assert!(3 * piop_dom < pcs_dom_size);
            // but 3 * (2 * piop) + 1 > pcs (piop is maximal)
            assert!(3 * (2 * piop_dom) + 1 > pcs_dom_size);
            // max_ring should map back to this piop
            assert_eq!(piop_domain_size::<S>(max_ring), piop_dom);
            // max_ring + 1 should require larger piop
            assert!(piop_domain_size::<S>(max_ring + 1) > piop_dom);
        }

        // Edge case: ring_size = 0 (degenerate but shouldn't panic)
        let piop_zero = piop_domain_size::<S>(0);
        assert!(piop_zero.is_power_of_two());
        assert_eq!(piop_zero, overhead.next_power_of_two());
    }

    #[macro_export]
    macro_rules! ring_suite_tests {
        ($suite:ty) => {
            mod ring {
                use super::*;

                #[test]
                fn prove_verify() {
                    $crate::ring::testing::prove_verify::<$suite>()
                }

                #[test]
                fn prove_verify_batch() {
                    $crate::ring::testing::prove_verify_batch::<$suite>()
                }

                #[test]
                fn padding_check() {
                    $crate::ring::testing::padding_check::<$suite>()
                }

                #[test]
                fn accumulator_base_check() {
                    $crate::ring::testing::accumulator_base_check::<$suite>()
                }

                #[test]
                fn verifier_key_builder() {
                    $crate::ring::testing::verifier_key_builder::<$suite>()
                }

                #[test]
                fn domain_size_conversions() {
                    $crate::ring::testing::domain_size_conversions::<$suite>()
                }

                $crate::test_vectors!($crate::ring::testing::TestVector<$suite>);
            }
        };
    }

    pub trait RingSuiteExt: RingSuite + crate::testing::SuiteExt {
        const SRS_FILE: &str;

        fn params() -> &'static RingProofParams<Self>;

        #[allow(unused)]
        fn load_context() -> RingProofParams<Self> {
            use ark_serialize::CanonicalDeserialize;
            use std::{fs::File, io::Read};
            let mut file = File::open(Self::SRS_FILE).unwrap();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).unwrap();
            let pcs_params =
                PcsParams::<Self>::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
            RingProofParams::from_pcs_params(crate::ring::testing::TEST_RING_SIZE, pcs_params)
                .unwrap()
        }

        #[allow(unused)]
        fn write_context(params: &RingProofParams<Self>) {
            use ark_serialize::CanonicalSerialize;
            use std::{fs::File, io::Write};
            let mut file = File::create(Self::SRS_FILE).unwrap();
            let mut buf = Vec::new();
            params.pcs.serialize_uncompressed(&mut buf).unwrap();
            file.write_all(&buf).unwrap();
        }
    }

    pub struct TestVector<S: RingSuite> {
        pub pedersen: pedersen::testing::TestVector<S>,
        pub ring_pks: [AffinePoint<S>; TEST_RING_SIZE],
        pub ring_pks_com: RingCommitment<S>,
        pub ring_proof: RingBareProof<S>,
    }

    impl<S: RingSuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TestVector")
                .field("pedersen", &self.pedersen)
                .field("ring_proof", &"...")
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: RingSuiteExt + std::fmt::Debug + 'static,
    {
        fn name() -> String {
            S::suite_name() + "_ring"
        }

        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let pedersen = pedersen::testing::TestVector::new(comment, seed, alpha, salt, ad);

            let secret = Secret::<S>::from_scalar(pedersen.base.sk);
            let public = secret.public();

            let input = Input::<S>::from(pedersen.base.h);
            let output = Output::from(pedersen.base.gamma);

            let params = <S as RingSuiteExt>::params();

            use ark_std::rand::SeedableRng;
            let rng = &mut rand_chacha::ChaCha20Rng::from_seed([0x11; 32]);
            let prover_idx = 3;
            let mut ring_pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
            ring_pks[prover_idx] = public.0;

            let prover_key = params.prover_key(&ring_pks);
            let prover = params.prover(prover_key, prover_idx);
            let proof = secret.prove(input, output, ad, &prover);

            let verifier_key = params.verifier_key(&ring_pks);
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
            let ring_proof = map.get::<RingBareProof<S>>("ring_proof");

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

            let params = <S as RingSuiteExt>::params();

            let prover_idx = self.ring_pks.iter().position(|&pk| pk == public.0).unwrap();

            let prover_key = params.prover_key(&self.ring_pks);
            let prover = params.prover(prover_key, prover_idx);

            let verifier_key = params.verifier_key(&self.ring_pks);
            let verifier = params.verifier(verifier_key);

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
