//! # Ring VRF
//!
//! Anonymized ring VRF combining Pedersen VRF with the ring proof scheme derived
//! from [CSSV22](https://eprint.iacr.org/2022/1205). Proves that a single blinded
//! key is a member of a committed ring without revealing which one.
//!
//! This module is gated by the `ring` feature.
//!
//! The ring prover draws its column blinding from the OS random source and
//! panics at `prove` where `getrandom` has no source.
//! [`RingContext::new_without_blinding`] skips the draw, and the zero
//! knowledge with it.
//!
//! ## Setup
//!
//! A deployment builds its [`RingSetup`] from the SRS of a trusted setup
//! ceremony with [`RingSetup::from_pcs_params`]. The repository ships the
//! Zcash ceremony SRS in `data/srs/`. [`RingSetup::from_seed_insecure`] and
//! [`RingSetup::from_rand_insecure`] generate the trapdoor locally and are
//! for tests only.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::ring::{Prover, Verifier};
//!
//! const RING_SIZE: usize = 100;
//! let prover_key_index = 3;
//!
//! // Create a ring of public keys
//! let mut ring = (0..RING_SIZE)
//!     .map(|i| {
//!         let mut seed = [0u8; 32];
//!         seed[..8].copy_from_slice(&i.to_le_bytes());
//!         Secret::from_seed(seed).public().point()
//!     })
//!     .collect::<Vec<_>>();
//! ring[prover_key_index] = public.point();
//!
//! // Initialize ring parameters
//! let ring_setup = RingSetup::from_seed_insecure(RING_SIZE, [0x42; 32]);
//! let ring_ctx = ring_setup.ring_context();
//!
//! // Proving
//! let prover_key = ring_setup.prover_key(&ring).unwrap();
//! let prover = ring_ctx.ring_prover(prover_key, prover_key_index);
//! let io = secret.vrf_io(input);
//! let proof = secret.prove(io, b"aux data", &prover);
//!
//! // Verification
//! let verifier_key = ring_setup.verifier_key(&ring).unwrap();
//! let verifier = ring_ctx.ring_verifier(verifier_key);
//! let result = Public::verify(io, b"aux data", &proof, &verifier);
//!
//! // Efficient verification with commitment
//! let ring_commitment = verifier_key.commitment();
//! let reconstructed_key = ring_setup.verifier_key_from_commitment(ring_commitment);
//!
//! // Same, without the setup: the PCS verifier params are a few points,
//! // independent of ring size, and can be distributed separately.
//! let pcs_params = ring_setup.pcs_verifier_params();
//! let reconstructed_key =
//!     ark_vrf::ring::verifier_key_from_commitment::<BandersnatchSha512Ell2>(ring_commitment, pcs_params);
//! ```

use crate::*;
use ark_ec::{
    pairing::Pairing,
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_std::{borrow::Cow, ops::Range};
use pedersen::{PedersenSuite, Proof as PedersenProof};
use utils::canonical::deserialize_canonical;
use utils::te_sw_map::TEMapping;
use w3f_ring_proof as ring_proof;

/// Seed hashed to curve to produce [`RingSuite::ACCUMULATOR_BASE`] in built-in suites.
pub const ACCUMULATOR_BASE_SEED: &[u8] = b"ring-accumulator";

/// Seed hashed to curve to produce [`RingSuite::PADDING`] in built-in suites.
pub const PADDING_SEED: &[u8] = b"ring-padding";

/// Suite extension for Ring VRF support.
///
/// Provides the additional cryptographic parameters required by the Ring VRF
/// scheme. The bounds on the associated type are the ones the ring proof
/// backend requires.
pub trait RingSuite:
    PedersenSuite<
    Affine: AffineRepr<
        BaseField: ark_ff::PrimeField + ring_proof::CondSelect,
        Config: TECurveConfig + Clone,
    > + TEMapping<<Self::Affine as AffineRepr>::Config>,
>
{
    /// Pairing type.
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    /// Accumulator base.
    ///
    /// Point with unknown discrete log relative to the generator. It must not
    /// be the identity. Membership in the prime order subgroup is not
    /// required: built-in Twisted Edwards suites hash [`ACCUMULATOR_BASE_SEED`]
    /// to the curve, while the Short Weierstrass Bandersnatch suite adds a
    /// fixed point outside the prime order subgroup to the hashed point.
    const ACCUMULATOR_BASE: AffinePoint<Self>;

    /// Padding point.
    ///
    /// Point with unknown discrete log relative to the generator, usable in
    /// place of any key during ring construction. Built-in suites derive it by
    /// hashing [`PADDING_SEED`] to the curve.
    const PADDING: AffinePoint<Self>;
}

/// KZG Polynomial Commitment Scheme.
pub type Kzg<S> = ring_proof::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG commitment.
pub type PcsCommitment<S> = <Kzg<S> as ring_proof::pcs::PCS<BaseField<S>>>::C;

/// KZG Polynomial Commitment Scheme parameters.
///
/// Basically powers of tau SRS.
pub type PcsParams<S> = ring_proof::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

/// PCS parameters required by the verifier.
///
/// A few points extracted from the SRS, independent of ring size. Together
/// with a [`RingCommitment`] it is sufficient to reconstruct a
/// [`RingVerifierKey`] via [`verifier_key_from_commitment`], without access
/// to the full [`RingSetup`]. See [`RingVerifierKey`] for the uncompressed
/// decode caveat.
pub type PcsVerifierParams<S> = <PcsParams<S> as ring_proof::pcs::PcsParams>::RVK;

/// Polynomial Interactive Oracle Proof (IOP) parameters.
///
/// Basically all the application specific parameters required to construct and
/// verify the ring proof.
pub type PiopParams<S> = ring_proof::PiopParams<TEAffine<CurveConfig<S>>>;

/// Ring keys commitment.
///
/// See [`RingVerifierKey`] for the uncompressed decode caveat.
pub type RingCommitment<S> = ring_proof::FixedColumnsCommitted<BaseField<S>, PcsCommitment<S>>;

/// Ring prover key.
pub type RingProverKey<S> = ring_proof::ProverKey<BaseField<S>, Kzg<S>, TEAffine<CurveConfig<S>>>;

/// Ring verifier key.
///
/// A backend type with the arkworks decoder, which does not check that an
/// uncompressed BLS12-381 point is on the curve. After an uncompressed decode
/// of untrusted bytes call `Valid::check`, or use the compressed form. The
/// same holds for [`RingCommitment`] and [`PcsVerifierParams`].
pub type RingVerifierKey<S> = ring_proof::VerifierKey<BaseField<S>, Kzg<S>>;

/// Ring prover.
pub type RingProver<S> = ring_proof::ring_prover::RingProver<BaseField<S>, Kzg<S>, CurveConfig<S>>;

/// Ring verifier.
pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, Kzg<S>, CurveConfig<S>>;

/// Multi-ring KZG batch verifier.
///
/// Accumulates ring proofs from one or more rings (sharing the same KZG SRS)
/// into a single batched pairing check.
pub type RingBatchVerifier<S> = ring_proof::multi_ring_batch_verifier::BatchVerifier<
    <S as RingSuite>::Pairing,
    ring_proof::ArkTranscript,
>;

/// Raw ring proof.
///
/// This is the primitive ring proof used in conjunction with Pedersen proof to
/// construct the actual ring vrf proof [`Proof`].
pub type RingBareProof<S> = ring_proof::RingProof<BaseField<S>, Kzg<S>>;

/// Ring VRF proof.
///
/// Pedersen VRF proof combined with a ring membership proof:
/// - `pedersen_proof`: Key commitment and VRF correctness proof
/// - `ring_proof`: Membership proof binding the key commitment `Yb` to the ring
///
/// Construct it with [`Prover::prove`] or by deserialization. Deserialization
/// via [`CanonicalDeserialize`] includes subgroup checks for curve points, so
/// every proof holds valid points unless built with a `deserialize_*_unchecked`
/// method.
///
/// Both paths accept one encoding per proof and do not reject trailing bytes.
#[derive(Clone, CanonicalSerialize)]
pub struct Proof<S: RingSuite> {
    /// Pedersen VRF proof (key commitment and VRF correctness).
    pub(crate) pedersen_proof: PedersenProof<S>,
    /// Ring membership proof binding the key commitment to the ring.
    pub(crate) ring_proof: RingBareProof<S>,
}

/// Stack buffer for the canonical decode of a ring proof, 928 bytes
/// uncompressed on BLS12-381.
const RING_PROOF_BUF_SIZE: usize = 1024;

impl<S: RingSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let pedersen_proof =
            PedersenProof::<S>::deserialize_with_mode(&mut reader, compress, validate)?;
        let ring_proof = deserialize_canonical::<RingBareProof<S>, RING_PROOF_BUF_SIZE>(
            &mut reader,
            compress,
            validate,
        )?;
        Ok(Proof {
            pedersen_proof,
            ring_proof,
        })
    }
}

impl<S: RingSuite> ark_serialize::Valid for Proof<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        ark_serialize::Valid::check(&self.pedersen_proof)?;
        ark_serialize::Valid::check(&self.ring_proof)
    }
}

impl<S: RingSuite + core::fmt::Debug> core::fmt::Debug for Proof<S> {
    /// The backend ring proof type has no `Debug`; its serialized size stands in.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Proof")
            .field("pedersen_proof", &self.pedersen_proof)
            .field(
                "ring_proof",
                &format_args!("<{} bytes>", self.ring_proof.compressed_size()),
            )
            .finish()
    }
}

/// Trait for types that can generate Ring VRF proofs.
pub trait Prover<S: RingSuite> {
    /// Generate a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before proving.
    /// `prover` must be built for the ring and for the position of this key in
    /// it (see [`RingContext::ring_prover`]).
    fn prove(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        prover: &RingProver<S>,
    ) -> Proof<S>;
}

/// Trait for types that can verify Ring VRF proofs.
///
/// Verifies that a VRF output was correctly derived using a secret key
/// belonging to one of the ring's public keys, without revealing which one.
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
///
/// The group identity is checked unconditionally, for the key commitment and
/// for every I/O pair, by the embedded Pedersen verification (see
/// [`pedersen::Verifier`]).
pub trait Verifier<S: RingSuite> {
    /// Verify a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before verifying.
    /// `verifier` must be built for the ring the proof claims membership in
    /// (see [`RingContext::ring_verifier`]).
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::InvalidData)` if the
    /// key commitment or any I/O pair point is the group identity or the key
    /// commitment cannot be mapped to Twisted Edwards form,
    /// `Err(Error::VerificationFailure)` otherwise.
    ///
    /// Subgroup membership of the points is not re-checked here. It is
    /// guaranteed by the checked constructors and checked deserialization of
    /// the point wrappers (see [`PointWrapper`]).
    fn verify(
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> Prover<S> for Secret<S> {
    fn prove(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        ring_prover: &RingProver<S>,
    ) -> Proof<S> {
        use pedersen::Prover as PedersenProver;
        let (pedersen_proof, mut secret_blinding) =
            <Self as PedersenProver<S>>::prove(self, ios, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        secret_blinding.zeroize();
        Proof {
            pedersen_proof,
            ring_proof,
        }
    }
}

impl<S: RingSuite> Verifier<S> for Public<S> {
    fn verify(
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error> {
        use pedersen::Verifier as PedersenVerifier;
        <Self as PedersenVerifier<S>>::verify(ios, ad, &proof.pedersen_proof)?;
        let key_commitment = proof
            .pedersen_proof
            .key_commitment()
            .into_te()
            .ok_or(Error::InvalidData)?;
        if !verifier.verify(proof.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

/// Lightweight ring proof context.
///
/// Contains only the PIOP parameters needed to construct prover and verifier
/// instances from pre-built keys, without the KZG SRS required for key generation.
///
/// Cheap to construct from a ring size alone via [`RingContext::new`], or
/// extractable from a [`RingSetup`] via [`RingSetup::ring_context`].
/// [`Self::piop_params`] reads the parameters.
#[derive(Clone)]
pub struct RingContext<S: RingSuite> {
    /// PIOP parameters.
    piop_params: PiopParams<S>,
}

/// Bring `key_index` into `[0, capacity)` without a division: the index is a
/// secret, and a hardware divider has an operand dependent latency.
fn wrap_key_index(key_index: usize, capacity: usize) -> usize {
    let masked = key_index & (capacity.next_power_of_two() - 1);
    masked.checked_sub(capacity).unwrap_or(masked)
}

impl<S: RingSuite> RingContext<S> {
    /// Construct a context for a ring of at least `min_ring_size` keys.
    ///
    /// [`Self::max_ring_size`] reports the exact capacity. A `min_ring_size`
    /// of 0 counts as 1.
    pub fn new(min_ring_size: usize) -> Self {
        Self::construct(min_ring_size, true)
    }

    /// Construct a context whose provers generate deterministic proofs.
    ///
    /// Column blinding is disabled: proofs are reproducible, thus NOT zero-knowledge,
    /// but remain valid for verifiers using a regular context for the same ring size.
    /// Useful for reproducible test vectors generation.
    pub fn new_without_blinding(min_ring_size: usize) -> Self {
        Self::construct(min_ring_size, false)
    }

    fn construct(min_ring_size: usize, blinding: bool) -> Self {
        let domain_size = piop_domain_size::<S>(min_ring_size);
        let mut domain =
            ring_proof::Domain::with_zk_rows(domain_size, ring_proof::piop::params::ZK_ROWS);
        if !blinding {
            domain = domain.without_blinding();
        }
        let piop_params = PiopParams::<S>::setup(
            domain,
            S::BLINDING_BASE
                .into_te()
                .expect("BLINDING_BASE must not be identity"),
            S::ACCUMULATOR_BASE
                .into_te()
                .expect("ACCUMULATOR_BASE must not be identity"),
            S::PADDING.into_te().expect("PADDING must not be identity"),
        );
        Self { piop_params }
    }

    /// The max ring size this context is able to handle.
    #[inline(always)]
    pub fn max_ring_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    /// Get a reference to the PIOP parameters.
    pub fn piop_params(&self) -> &PiopParams<S> {
        &self.piop_params
    }

    /// Create a prover instance for a specific position in the ring.
    ///
    /// An index at or beyond [`Self::max_ring_size`] wraps into range. A wrong
    /// index gives a proof that no verifier accepts. `prover_key` must come
    /// from a setup with the domain of this context.
    pub fn ring_prover(&self, prover_key: RingProverKey<S>, key_index: usize) -> RingProver<S> {
        self.clone().into_ring_prover(prover_key, key_index)
    }

    /// Create a verifier instance from a verifier key.
    pub fn ring_verifier(&self, verifier_key: RingVerifierKey<S>) -> RingVerifier<S> {
        self.clone().into_ring_verifier(verifier_key)
    }

    /// Create a prover instance, consuming the context to avoid cloning.
    ///
    /// See [`Self::ring_prover`] for the handling of `key_index`.
    pub fn into_ring_prover(self, prover_key: RingProverKey<S>, key_index: usize) -> RingProver<S> {
        let key_index = wrap_key_index(key_index, self.max_ring_size());
        RingProver::<S>::init(
            prover_key,
            self.piop_params,
            key_index,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Create a verifier instance, consuming the context to avoid cloning.
    pub fn into_ring_verifier(self, verifier_key: RingVerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop_params,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }
}

/// Ring proof setup.
///
/// Contains the cryptographic parameters needed for ring proof key construction,
/// proving and verification:
/// - `pcs_params`: Polynomial Commitment Scheme parameters (KZG setup)
/// - `ring_ctx`: Ring context containing the PIOP parameters
///
/// The serialized form is the SRS, trimmed to the domain, so the G1 length
/// carries the ring capacity and decoding accepts only that exact shape. A raw
/// SRS file is not a setup: decode it as [`PcsParams`] and call
/// [`Self::from_pcs_params`].
#[derive(Clone)]
pub struct RingSetup<S: RingSuite> {
    /// PCS parameters.
    pcs_params: PcsParams<S>,
    /// Ring context (PIOP parameters).
    ring_ctx: RingContext<S>,
}

/// The ring proof backend asserts on the identity, so it is rejected here.
fn ring_members_te<S: RingSuite>(
    pks: &[AffinePoint<S>],
) -> Result<Cow<'_, [TEAffine<CurveConfig<S>>]>, Error> {
    if pks.iter().any(AffineRepr::is_zero) {
        return Err(Error::InvalidData);
    }
    TEMapping::to_te_slice(pks).ok_or(Error::InvalidData)
}

impl<S: RingSuite> RingSetup<S> {
    /// Construct deterministic ring proof params for a ring of at least
    /// `min_ring_size` keys.
    ///
    /// Creates parameters using a transcript-based RNG seeded with `seed`.
    ///
    /// # Insecure
    ///
    /// Anyone who knows the seed knows the KZG trapdoor and can forge ring
    /// proofs. For tests only; a deployment uses [`Self::from_pcs_params`].
    pub fn from_seed_insecure(min_ring_size: usize, seed: [u8; 32]) -> Self {
        let mut t = S::Transcript::new(S::SUITE_ID);
        t.absorb_raw(&seed);
        let mut rng = t.to_rng();
        Self::from_rand_insecure(min_ring_size, &mut rng)
    }

    /// Construct random ring proof params for a ring of at least `min_ring_size`
    /// keys.
    ///
    /// Generates a new KZG setup with sufficient degree for that ring size.
    ///
    /// # Insecure
    ///
    /// Whoever runs the generation knows the KZG trapdoor and can forge ring
    /// proofs. For tests only; a deployment uses [`Self::from_pcs_params`].
    pub fn from_rand_insecure(min_ring_size: usize, rng: &mut impl ark_std::rand::RngCore) -> Self {
        use ring_proof::pcs::PCS;
        let max_degree = pcs_domain_size::<S>(min_ring_size) - 1;
        let pcs_params = Kzg::<S>::setup(max_degree, rng);
        Self::from_pcs_params(min_ring_size, pcs_params).expect("PCS params is correct")
    }

    /// Construct ring proof params from existing KZG setup.
    ///
    /// Truncates the setup if larger than needed, or returns
    /// `Error::RingCapacityExceeded` if it is insufficient for `min_ring_size` keys.
    ///
    /// Ring VRF soundness rests on the KZG trapdoor staying unknown, so
    /// `pcs_params` must come from a trusted setup ceremony. The repository
    /// ships the Zcash ceremony SRS for the BLS12-381 suites in
    /// `data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin`, which holds
    /// 1791 Bandersnatch or 1792 Jubjub keys.
    pub fn from_pcs_params(
        min_ring_size: usize,
        mut pcs_params: PcsParams<S>,
    ) -> Result<Self, Error> {
        let pcs_domain_size = pcs_domain_size::<S>(min_ring_size);
        if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
            return Err(Error::RingCapacityExceeded);
        }
        // Keep only the required powers of tau
        pcs_params.powers_in_g1.truncate(pcs_domain_size);
        pcs_params.powers_in_g2.truncate(2);

        Ok(Self {
            pcs_params,
            ring_ctx: RingContext::new(min_ring_size),
        })
    }

    /// Create a prover key for the given ring of public keys.
    ///
    /// Returns `Error::RingCapacityExceeded` if `pks` exceeds the max ring size,
    /// `Error::InvalidData` if a key is the identity or cannot be mapped to
    /// Twisted Edwards form.
    pub fn prover_key(&self, pks: &[AffinePoint<S>]) -> Result<RingProverKey<S>, Error> {
        if pks.len() > self.ring_ctx.max_ring_size() {
            return Err(Error::RingCapacityExceeded);
        }
        let pks = ring_members_te::<S>(pks)?;
        Ok(ring_proof::index(&self.pcs_params, &self.ring_ctx.piop_params, &pks).0)
    }

    /// Create a verifier key for the given ring of public keys.
    ///
    /// Returns `Error::RingCapacityExceeded` if `pks` exceeds the max ring size,
    /// `Error::InvalidData` if a key is the identity or cannot be mapped to
    /// Twisted Edwards form.
    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> Result<RingVerifierKey<S>, Error> {
        if pks.len() > self.ring_ctx.max_ring_size() {
            return Err(Error::RingCapacityExceeded);
        }
        let pks = ring_members_te::<S>(pks)?;
        Ok(ring_proof::index(&self.pcs_params, &self.ring_ctx.piop_params, &pks).1)
    }

    /// Create a verifier key from a precomputed ring commitment.
    ///
    /// The commitment can be obtained from an existing verifier key via
    /// [`RingVerifierKey::commitment`].
    pub fn verifier_key_from_commitment(
        &self,
        commitment: RingCommitment<S>,
    ) -> RingVerifierKey<S> {
        verifier_key_from_commitment::<S>(commitment, self.pcs_verifier_params())
    }

    /// Extract the PCS parameters required by the verifier.
    ///
    /// Small (a few points) and independent of ring size. Sufficient,
    /// together with a ring commitment, to reconstruct a verifier key via
    /// [`verifier_key_from_commitment`] without access to the full setup.
    pub fn pcs_verifier_params(&self) -> PcsVerifierParams<S> {
        use ring_proof::pcs::PcsParams;
        self.pcs_params.raw_vk()
    }

    /// Create a builder for incremental construction of the verifier key.
    pub fn verifier_key_builder(&self) -> (VerifierKeyBuilder<S>, RingBuilderPcsParams<S>) {
        type RingBuilderKey<S> =
            ring_proof::ring::RingBuilderKey<BaseField<S>, <S as RingSuite>::Pairing>;
        let piop_domain_size = piop_domain_size::<S>(self.ring_ctx.max_ring_size());
        let builder_key = RingBuilderKey::<S>::from_srs(&self.pcs_params, piop_domain_size);
        let builder_pcs_params = RingBuilderPcsParams(builder_key.lis_in_g1);
        let builder = VerifierKeyBuilder::new(self, &builder_pcs_params)
            .expect("the builder key covers the whole domain");
        (builder, builder_pcs_params)
    }

    /// Get a reference to the PCS parameters: the SRS, trimmed to the domain.
    pub fn pcs_params(&self) -> &PcsParams<S> {
        &self.pcs_params
    }

    /// Get a reference to the lightweight [`RingContext`].
    pub fn ring_context(&self) -> &RingContext<S> {
        &self.ring_ctx
    }

    /// Get the padding point.
    ///
    /// This is a point of unknown dlog that can be used in place of any key during
    /// ring construction.
    #[inline(always)]
    pub const fn padding_point() -> AffinePoint<S> {
        S::PADDING
    }
}

/// Create a verifier key from a precomputed ring commitment and the PCS
/// verifier parameters.
///
/// Lightweight alternative to [`RingSetup::verifier_key_from_commitment`] for
/// verifier-only users: no SRS required. The parameters can be obtained once
/// via [`RingSetup::pcs_verifier_params`] and distributed independently.
///
/// Soundness rests on `pcs_params` matching the trusted setup the commitment
/// was produced under. Deserialization validates the points, but cannot tell
/// a legitimate setup from a malicious one: obtain the parameters from a
/// trusted source, not alongside untrusted proof data.
pub fn verifier_key_from_commitment<S: RingSuite>(
    commitment: RingCommitment<S>,
    pcs_params: PcsVerifierParams<S>,
) -> RingVerifierKey<S> {
    RingVerifierKey::<S>::from_commitment_and_kzg_vk(commitment, pcs_params)
}

impl<S: RingSuite> CanonicalSerialize for RingSetup<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.pcs_params.serialized_size(compress)
    }
}

impl<S: RingSuite> CanonicalDeserialize for RingSetup<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let pcs_params = <PcsParams<S> as CanonicalDeserialize>::deserialize_with_mode(
            reader, compress, validate,
        )?;
        let g1_powers = pcs_params.powers_in_g1.len();
        let max_ring_size = max_ring_size_from_pcs_domain_size::<S>(g1_powers)
            .ok_or(ark_serialize::SerializationError::InvalidData)?;
        if pcs_params.powers_in_g2.len() < 2 || pcs_domain_size::<S>(max_ring_size) != g1_powers {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(Self {
            pcs_params,
            ring_ctx: RingContext::new(max_ring_size),
        })
    }
}

impl<S: RingSuite> ark_serialize::Valid for RingSetup<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.check()
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
    ring_proof::ring::Ring<BaseField<S>, <S as RingSuite>::Pairing, TEAffine<CurveConfig<S>>>;

/// Builder for incremental construction of ring verifier keys.
///
/// Allows constructing a verifier key by adding public keys in batches,
/// which is useful for large rings or memory-constrained environments.
#[derive(Clone, CanonicalSerialize)]
pub struct VerifierKeyBuilder<S: RingSuite> {
    partial: PartialRingCommitment<S>,
    pcs_params: PcsVerifierParams<S>,
}

impl<S: RingSuite> CanonicalDeserialize for VerifierKeyBuilder<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let partial = PartialRingCommitment::<S>::deserialize_with_mode(
            &mut reader,
            compress,
            ark_serialize::Validate::No,
        )?;
        if partial.curr_keys > partial.max_keys {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let pcs_params = PcsVerifierParams::<S>::deserialize_with_mode(
            &mut reader,
            compress,
            ark_serialize::Validate::No,
        )?;
        let builder = Self {
            partial,
            pcs_params,
        };
        if matches!(validate, ark_serialize::Validate::Yes) {
            ark_serialize::Valid::check(&builder)?;
        }
        Ok(builder)
    }
}

impl<S: RingSuite> ark_serialize::Valid for VerifierKeyBuilder<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        ark_serialize::Valid::check(&self.partial)?;
        ark_serialize::Valid::check(&self.pcs_params)
    }
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
    /// Returns `Error::SrsLookupFailed` if `lookup` does not cover
    /// `max_ring_size..piop_domain_size`, the part of the SRS behind the keys.
    pub fn new(ring_setup: &RingSetup<S>, lookup: impl SrsLookup<S>) -> Result<Self, Error> {
        let keys = ring_setup.ring_ctx.max_ring_size();
        let tail = lookup
            .lookup(keys..piop_domain_size::<S>(keys))
            .ok_or(Error::SrsLookupFailed)?;
        let lookup = |range: Range<usize>| {
            debug_assert_eq!(tail.len(), range.len());
            Ok(tail.clone())
        };
        let pcs_params = ring_setup.pcs_verifier_params();
        let partial = PartialRingCommitment::<S>::empty(
            &ring_setup.ring_ctx.piop_params,
            lookup,
            pcs_params.g1.into_group(),
        );
        Ok(VerifierKeyBuilder {
            partial,
            pcs_params,
        })
    }

    /// Get the number of remaining slots available in the ring.
    #[inline(always)]
    pub fn free_slots(&self) -> usize {
        self.partial.max_keys - self.partial.curr_keys
    }

    /// Get the PCS parameters required by the verifier.
    ///
    /// Same value as [`RingSetup::pcs_verifier_params`] for the setup this
    /// builder was created from.
    pub fn pcs_verifier_params(&self) -> PcsVerifierParams<S> {
        self.pcs_params.clone()
    }

    /// Add public keys to the ring being built.
    ///
    /// On failure nothing is appended. Returns `Error::RingCapacityExceeded` if the
    /// keys do not fit in the ring ([`Self::free_slots`] gives the remaining
    /// capacity), `Error::SrsLookupFailed` if the SRS lookup fails,
    /// `Error::InvalidData` if a key is the identity or cannot be mapped to
    /// Twisted Edwards form.
    pub fn append(
        &mut self,
        pks: &[AffinePoint<S>],
        lookup: impl SrsLookup<S>,
    ) -> Result<(), Error> {
        if self.free_slots() < pks.len() {
            return Err(Error::RingCapacityExceeded);
        }
        // Currently `ring-proof` backend panics if lookup fails.
        // This workaround makes lookup failures a bit less harsh.
        let segment = lookup
            .lookup(self.partial.curr_keys..self.partial.curr_keys + pks.len())
            .ok_or(Error::SrsLookupFailed)?;
        let lookup = |range: Range<usize>| {
            debug_assert_eq!(segment.len(), range.len());
            Ok(segment.clone())
        };
        let pks = ring_members_te::<S>(pks)?;
        self.partial.append(&pks, lookup);
        Ok(())
    }

    /// Complete the building process and create the verifier key.
    pub fn finalize(self) -> RingVerifierKey<S> {
        RingVerifierKey::<S>::from_ring_and_kzg_vk(&self.partial, self.pcs_params)
    }
}

type RingProofBatchItem<S> =
    ring_proof::multi_ring_batch_verifier::BatchItem<<S as RingSuite>::Pairing, CurveConfig<S>>;

/// Deferred Ring VRF verification data for batch verification.
///
/// Holds the prepared Pedersen VRF item and the prepared ring proof item.
pub struct BatchItem<S: RingSuite> {
    ring: RingProofBatchItem<S>,
    pedersen: pedersen::BatchItem<S>,
}

impl<S: RingSuite> BatchItem<S> {
    /// Prepare a proof for batch verification.
    ///
    /// Performs the cheap per-proof work (hashing, transcript setup) without
    /// the expensive pairing and MSM checks, and packages all data needed for
    /// deferred verification in [`BatchVerifier::verify`]. This can be done in
    /// parallel. `verifier` must be the ring verifier the proof was produced
    /// against.
    ///
    /// Returns `Error::InvalidData` if the proof's key commitment cannot be
    /// mapped to Twisted Edwards form (e.g. identity point on SW-form suites).
    pub fn new(
        verifier: &RingVerifier<S>,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<Self, Error> {
        let key_commitment = proof
            .pedersen_proof
            .key_commitment()
            .into_te()
            .ok_or(Error::InvalidData)?;
        let pedersen = pedersen::BatchItem::new(ios, ad, &proof.pedersen_proof);
        let ring = RingProofBatchItem::<S>::new(verifier, proof.ring_proof.clone(), key_commitment);
        Ok(Self { ring, pedersen })
    }
}

/// Batch verifier for Ring VRF proofs.
///
/// Collects ring proofs from one or more rings (sharing the same KZG SRS)
/// and verifies them together, amortizing the cost of pairing checks and
/// multi-scalar multiplications.
///
/// The same subgroup membership assumptions as [`Verifier`] apply to all
/// points fed into the batch (I/O pairs and proof points).
pub struct BatchVerifier<S: RingSuite> {
    ring_batch: RingBatchVerifier<S>,
    pedersen_batch: pedersen::BatchVerifier<S>,
}

impl<S: RingSuite> BatchVerifier<S> {
    /// Create a new empty batch verifier.
    ///
    /// The KZG verifier key is taken from `ring_verifier`.
    /// Any ring verifier sharing the same SRS can later be passed to
    /// [`Self::push`] or [`BatchItem::new`]; the verifier supplied here is
    /// only used to extract the KZG verifier key.
    pub fn new(ring_verifier: &RingVerifier<S>) -> Self {
        Self {
            ring_batch: RingBatchVerifier::<S>::new(
                ring_verifier.pcs_vk().clone(),
                ring_proof::ArkTranscript::new(S::SUITE_ID),
            ),
            pedersen_batch: pedersen::BatchVerifier::new(),
        }
    }

    /// Push a previously prepared item into the batch.
    pub fn push_prepared(&mut self, item: BatchItem<S>) {
        self.pedersen_batch.push_prepared(item.pedersen);
        self.ring_batch.push_prepared(item.ring);
    }

    /// Prepare and push a proof in one step.
    ///
    /// Returns `Error::InvalidData` if the proof's key commitment cannot be
    /// mapped to Twisted Edwards form (e.g. identity point on SW-form suites).
    pub fn push(
        &mut self,
        verifier: &RingVerifier<S>,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let item = BatchItem::new(verifier, ios, ad, proof)?;
        self.push_prepared(item);
        Ok(())
    }

    /// Batch-verify all collected proofs.
    ///
    /// Checks the Pedersen proofs with a single multi-scalar multiplication
    /// and the ring proofs with a single batched pairing check.
    ///
    /// Returns `Ok(())` if all proofs verify, `Err(Error::InvalidData)` if any
    /// key commitment or I/O pair point is the group identity,
    /// `Err(Error::VerificationFailure)` otherwise.
    ///
    /// Subgroup membership of the points is not re-checked here. It is
    /// guaranteed by the checked constructors and checked deserialization of
    /// the point wrappers (see [`PointWrapper`]).
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
        pub type PcsVerifierParams = $crate::ring::PcsVerifierParams<$suite>;
        #[allow(dead_code)]
        pub type PiopParams = $crate::ring::PiopParams<$suite>;
        #[allow(dead_code)]
        pub type RingContext = $crate::ring::RingContext<$suite>;
        #[allow(dead_code)]
        pub type RingSetup = $crate::ring::RingSetup<$suite>;
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
/// The ring proof system operates with four related size parameters:
///
/// 1. `min_ring_size`: Number of keys that the ring should accommodate (user-facing parameter)
/// 2. `max_ring_size`: Max number of keys that the ring can accommodate
/// 3. `piop_domain_size`: Size of the PIOP (Polynomial IOP) domain
/// 4. `pcs_domain_size`: Size of the PCS (Polynomial Commitment Scheme) domain
///
/// Relationships:
///   piop_domain_size = (max(min_ring_size, 1) + PIOP_OVERHEAD).next_power_of_two()
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
        piop_domain_size::<S>(min_ring_size) - piop_overhead::<S>()
    }

    /// PIOP overhead: accounts for 3 ZK blinding points + 1 internal point + scalar field bits.
    pub const fn piop_overhead<S: Suite>() -> usize {
        4 + ScalarField::<S>::MODULUS_BIT_SIZE as usize
    }

    /// PIOP domain size required to support the given ring size.
    ///
    /// Returns the smallest power of 2 that can accommodate `min_ring_size` members.
    /// This is the domain size used for polynomial operations in the ring proof and
    /// already accounts for the PIOP overhead. A `min_ring_size` of 0 counts as 1.
    pub const fn piop_domain_size<S: Suite>(min_ring_size: usize) -> usize {
        let min_ring_size = if min_ring_size == 0 { 1 } else { min_ring_size };
        (min_ring_size + piop_overhead::<S>()).next_power_of_two()
    }

    /// Maximum ring size supported by a given PIOP domain size.
    ///
    /// Returns the largest ring that fits in the domain, or `None` when the
    /// domain holds no key.
    pub const fn max_ring_size_from_piop_domain_size<S: Suite>(
        piop_domain_size: usize,
    ) -> Option<usize> {
        if piop_domain_size > piop_overhead::<S>() {
            Some(piop_domain_size - piop_overhead::<S>())
        } else {
            None
        }
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
    /// Rounds down to a power of two. Returns `None` when `pcs_domain_size` is
    /// below 4.
    pub const fn piop_domain_size_from_pcs_domain_size(pcs_domain_size: usize) -> Option<usize> {
        match (pcs_domain_size.saturating_sub(1) / 3).checked_ilog2() {
            Some(log2) => Some(1 << log2),
            None => None,
        }
    }

    /// Maximum ring size supported by a given PCS domain size.
    ///
    /// Composes `piop_domain_size_from_pcs_domain_size` and
    /// `max_ring_size_from_piop_domain_size`. Returns `None` when no domain fits.
    pub const fn max_ring_size_from_pcs_domain_size<S: Suite>(
        pcs_domain_size: usize,
    ) -> Option<usize> {
        match piop_domain_size_from_pcs_domain_size(pcs_domain_size) {
            Some(piop_domain_size) => max_ring_size_from_piop_domain_size::<S>(piop_domain_size),
            None => None,
        }
    }
}
pub use dom_utils::*;

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

    struct TestItem<S: RingSuite> {
        io: VrfIo<S>,
        ad: Vec<u8>,
        proof: Proof<S>,
    }

    impl<S: RingSuite> TestItem<S> {
        fn new(
            secret: &Secret<S>,
            prover: &RingProver<S>,
            rng: &mut dyn ark_std::rand::RngCore,
        ) -> Self {
            let input = Input::from_affine_unchecked(common::random_val(Some(rng)));
            let io = secret.vrf_io(input);
            let ad_len = common::random_val::<usize>(Some(rng)) % (MAX_AD_LEN + 1);
            let ad = common::random_vec(ad_len, Some(rng));
            let proof = secret.prove(io, &ad, prover);
            Self { io, ad, proof }
        }
    }

    #[allow(unused)]
    pub fn prove_verify<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = public.0;

        let ring_ctx = ring_setup.ring_context();
        let prover_key = ring_setup.prover_key(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);

        let item = TestItem::<S>::new(&secret, &prover, rng);

        let verifier_key = ring_setup.verifier_key(&pks).unwrap();
        let verifier = ring_ctx.ring_verifier(verifier_key);
        let result = Public::verify(item.io, &item.ad, &item.proof, &verifier);
        assert!(result.is_ok());
    }

    /// One proof, one encoding. With an empty I/O list `Ok` is the identity,
    /// which arkworks reads from several byte strings; a relay could turn one
    /// valid proof into different bytes that also verify. The ring part goes
    /// through the same canonical check.
    pub fn proof_encoding_is_canonical<S: RingSuite>() {
        use ark_serialize::Compress;
        use ring::{Prover, Verifier};

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = secret.public().0;
        let ring_ctx = ring_setup.ring_context();
        let prover = ring_ctx.ring_prover(ring_setup.prover_key(&pks).unwrap(), prover_idx);
        let verifier = ring_ctx.ring_verifier(ring_setup.verifier_key(&pks).unwrap());

        let ios: [VrfIo<S>; 0] = [];
        let proof = secret.prove(ios, b"foo", &prover);
        assert!(proof.pedersen_proof.ok.is_zero());

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(Public::verify(ios, b"foo", &decoded, &verifier).is_ok());
        let mut reencoded = Vec::new();
        decoded.serialize_compressed(&mut reencoded).unwrap();
        assert_eq!(bytes, reencoded);

        let point_len = proof.pedersen_proof.pk_com.compressed_size();
        let ok_range = 2 * point_len..3 * point_len;
        let aliases = common::assert_aliases_rejected::<AffinePoint<S>>(
            &bytes,
            ok_range,
            Compress::Yes,
            |bytes| {
                Proof::<S>::deserialize_compressed(bytes).is_ok()
                    || common::decodes_inside_vec::<Proof<S>>(bytes, Compress::Yes)
            },
        );
        assert!(!aliases.is_empty());

        // The ring part: the pairing curve decides whether aliases exist. The
        // generic arkworks encoding (BN254) ignores the sign flag of an
        // uncompressed point; the Zcash encoding of BLS12-381 is canonical by
        // itself, so nothing is found there.
        let mut bytes = Vec::new();
        proof.serialize_uncompressed(&mut bytes).unwrap();
        let decoded = Proof::<S>::deserialize_uncompressed(&bytes[..]).unwrap();
        assert!(Public::verify(ios, b"foo", &decoded, &verifier).is_ok());
        let ring_part = proof.pedersen_proof.uncompressed_size();
        let first_point = ring_part..ring_part + G1Affine::<S>::zero().uncompressed_size();
        common::assert_aliases_rejected::<G1Affine<S>>(
            &bytes,
            first_point,
            Compress::No,
            |bytes| {
                Proof::<S>::deserialize_uncompressed(bytes).is_ok()
                    || common::decodes_inside_vec::<Proof<S>>(bytes, Compress::No)
            },
        );
    }

    /// N=3 multi proof via ring prove/verify.
    #[allow(unused)]
    pub fn prove_verify_multi<S: RingSuite>() {
        use ring::{Prover, Verifier};

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = public.0;

        let ring_ctx = ring_setup.ring_context();
        let prover_key = ring_setup.prover_key(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);

        let verifier_key = ring_setup.verifier_key(&pks).unwrap();
        let verifier = ring_ctx.ring_verifier(verifier_key);

        let mut ios: Vec<VrfIo<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                secret.vrf_io(input)
            })
            .collect();
        ios.push(VrfIo {
            input: Input::from_affine_unchecked(S::Affine::generator()),
            output: Output::from_affine_unchecked(public.0),
        });

        let proof = secret.prove(&ios[..], b"bar", &prover);
        assert!(Public::verify(&ios[..], b"bar", &proof, &verifier).is_ok());

        // Tamper: wrong output on ios[1]
        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(Public::verify(&bad_ios[..], b"bar", &proof, &verifier).is_err());

        // Tamper: wrong ad
        assert!(Public::verify(&ios[..], b"baz", &proof, &verifier).is_err());
    }

    #[allow(unused)]
    pub fn prove_verify_batch<S: RingSuite>() {
        use rayon::prelude::*;

        const BATCH_SIZE: usize = 3 * TEST_RING_SIZE;

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = public.0;

        let ring_ctx = ring_setup.ring_context();
        let prover_key = ring_setup.prover_key(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);

        // Generate proofs in parallel
        let batch: Vec<_> = (0..BATCH_SIZE)
            .into_par_iter()
            .map_init(ark_std::test_rng, |rng, _| {
                TestItem::<S>::new(&secret, &prover, rng)
            })
            .collect();

        let verifier_key = ring_setup.verifier_key(&pks).unwrap();
        let verifier = ring_ctx.ring_verifier(verifier_key);

        // Batch verify all proofs
        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let res = batch_verifier.verify();
        assert!(res.is_ok());

        // Prove incrementally constructed batches
        for item in batch.iter() {
            batch_verifier
                .push(&verifier, item.io, &item.ad, &item.proof)
                .unwrap();
            let res = batch_verifier.verify();
            assert!(res.is_ok());
        }

        println!("Batch size = {BATCH_SIZE}");

        println!("============================================================");

        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let start = std::time::Instant::now();
        common::timed("Proofs push", || {
            for item in batch.iter() {
                batch_verifier
                    .push(&verifier, item.io, &item.ad, &item.proof)
                    .unwrap();
            }
        });
        common::timed("Unprepared batch verification", || batch_verifier.verify());
        println!("Total time: {:?}", start.elapsed());

        println!("============================================================");

        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let start = std::time::Instant::now();
        let prepared = common::timed("Proofs prepare", || {
            batch
                .par_iter()
                .map(|item| BatchItem::<S>::new(&verifier, item.io, &item.ad, &item.proof).unwrap())
                .collect::<Vec<_>>()
        });
        common::timed("Proofs push prepared", || {
            prepared
                .into_iter()
                .for_each(|p| batch_verifier.push_prepared(p))
        });
        common::timed("Prepared batch verification", || batch_verifier.verify());
        println!("Total time: {:?}", start.elapsed());

        println!("============================================================");

        // Multi-ring batch: build a second ring sharing the same KZG SRS,
        // then aggregate proofs from both rings into a single batch verifier.
        let mut pks_b = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx_b = 1;
        pks_b[prover_idx_b] = public.0;
        let prover_key_b = ring_setup.prover_key(&pks_b).unwrap();
        let prover_b = ring_ctx.ring_prover(prover_key_b, prover_idx_b);
        let verifier_key_b = ring_setup.verifier_key(&pks_b).unwrap();
        let verifier_b = ring_ctx.ring_verifier(verifier_key_b);

        let batch_b: Vec<_> = (0..TEST_RING_SIZE)
            .into_par_iter()
            .map_init(ark_std::test_rng, |rng, _| {
                TestItem::<S>::new(&secret, &prover_b, rng)
            })
            .collect();

        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        for item in batch.iter() {
            batch_verifier
                .push(&verifier, item.io, &item.ad, &item.proof)
                .unwrap();
        }
        for item in batch_b.iter() {
            batch_verifier
                .push(&verifier_b, item.io, &item.ad, &item.proof)
                .unwrap();
        }
        common::timed("Multi-ring batch verification", || batch_verifier.verify())
            .expect("multi-ring batch verifies");

        // Negative case: pushing a ring-B proof against verifier_a must not
        // produce a batch that verifies. This guards against the per-item
        // verifier argument being silently ignored.
        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let item_b = &batch_b[0];
        batch_verifier
            .push(&verifier, item_b.io, &item_b.ad, &item_b.proof)
            .unwrap();
        assert!(
            batch_verifier.verify().is_err(),
            "ring-B proof must not verify against verifier_a"
        );
    }

    /// Ring size violations must be told apart from malformed data: the
    /// caller fixes them with larger parameters, not by rejecting the input.
    #[allow(unused)]
    pub fn ring_size_exceeded<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let max_ring_size = ring_setup.ring_context().max_ring_size();
        let pks = common::random_vec::<AffinePoint<S>>(max_ring_size + 1, Some(rng));
        assert!(matches!(
            ring_setup.prover_key(&pks),
            Err(Error::RingCapacityExceeded)
        ));
        assert!(matches!(
            ring_setup.verifier_key(&pks),
            Err(Error::RingCapacityExceeded)
        ));

        // SRS sized for `TEST_RING_SIZE` cannot back a ring beyond its capacity.
        let pcs_params = ring_setup.pcs_params.clone();
        assert!(matches!(
            RingSetup::<S>::from_pcs_params(max_ring_size + 1, pcs_params),
            Err(Error::RingCapacityExceeded)
        ));
    }

    /// The ring proof backend asserts on the identity point. A member key
    /// equal to the identity must be rejected at the crate boundary, on
    /// every entry point that hands keys to the backend, and `append` must
    /// leave the builder unchanged.
    pub fn identity_in_ring_rejected<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        pks[0] = AffinePoint::<S>::zero();

        assert!(matches!(
            ring_setup.prover_key(&pks),
            Err(Error::InvalidData)
        ));
        assert!(matches!(
            ring_setup.verifier_key(&pks),
            Err(Error::InvalidData)
        ));

        let (mut vk_builder, lookup) = ring_setup.verifier_key_builder();
        let free_slots = vk_builder.free_slots();
        assert_eq!(
            vk_builder.append(&pks, &lookup).unwrap_err(),
            Error::InvalidData
        );
        assert_eq!(vk_builder.free_slots(), free_slots);
    }

    /// Scale a Short Weierstrass point by `(x, y) -> (u^2 x, u^3 y)`, an
    /// isomorphism onto `y^2 = x^3 + b u^6`. The arkworks group law of an
    /// `a = 0` curve never reads `b`, so the image is off the curve and still
    /// passes the subgroup test, which is the only test the BLS12-381 decoder
    /// runs on an uncompressed point under `Validate::Yes`.
    pub trait OffCurveAlias: Sized {
        fn off_curve_alias(&self) -> Self;
    }

    impl<C: SWCurveConfig> OffCurveAlias for SWAffine<C> {
        fn off_curve_alias(&self) -> Self {
            use ark_ff::Field;
            let (x, y) = self.xy().unwrap();
            let u = C::BaseField::from(2u64);
            let alias = SWAffine::new_unchecked(x * u.square(), y * u.square() * u);
            assert!(!alias.is_on_curve());
            assert!(alias.is_in_correct_subgroup_assuming_on_curve());
            alias
        }
    }

    /// A checked uncompressed decode must reject an off-curve pairing point,
    /// in a ring proof and in a verifier key builder. The unchecked decode
    /// takes it, and `check()` on the value rejects it. The pairing point
    /// feeds a pairing, and the proof docs promise that a checked decode
    /// holds valid points.
    pub fn off_curve_pairing_point_rejected<S: RingSuite>()
    where
        G1Affine<S>: OffCurveAlias,
    {
        use ring::Prover;

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = secret.public().0;
        let ring_ctx = ring_setup.ring_context();
        let prover = ring_ctx.ring_prover(ring_setup.prover_key(&pks).unwrap(), prover_idx);
        let input = Input::from_affine_unchecked(common::random_val(Some(rng)));
        let proof = secret.prove(secret.vrf_io(input), b"foo", &prover);

        let point_len = G1Affine::<S>::zero().uncompressed_size();
        let replace_with_alias = |bytes: &mut [u8], start: usize| {
            let range = start..start + point_len;
            let point = G1Affine::<S>::deserialize_uncompressed(&bytes[range.clone()]).unwrap();
            let mut alias = Vec::new();
            point
                .off_curve_alias()
                .serialize_uncompressed(&mut alias)
                .unwrap();
            bytes[range].copy_from_slice(&alias);
        };

        let mut bytes = Vec::new();
        proof.serialize_uncompressed(&mut bytes).unwrap();
        replace_with_alias(&mut bytes, proof.pedersen_proof.uncompressed_size());
        assert!(Proof::<S>::deserialize_uncompressed(&bytes[..]).is_err());
        let unchecked = Proof::<S>::deserialize_uncompressed_unchecked(&bytes[..]).unwrap();
        assert!(ark_serialize::Valid::check(&unchecked).is_err());

        // `cx` of the partial ring commitment is the first field of the builder.
        let (builder, _) = ring_setup.verifier_key_builder();
        let mut bytes = Vec::new();
        builder.serialize_uncompressed(&mut bytes).unwrap();
        replace_with_alias(&mut bytes, 0);
        assert!(VerifierKeyBuilder::<S>::deserialize_uncompressed(&bytes[..]).is_err());
        let unchecked =
            VerifierKeyBuilder::<S>::deserialize_uncompressed_unchecked(&bytes[..]).unwrap();
        assert!(ark_serialize::Valid::check(&unchecked).is_err());
    }

    /// The bytes of a `RingSetup` may come from a file or from a peer. The
    /// encoding is the SRS alone, trimmed by the constructors to the powers
    /// its domain needs, so the G1 length carries the ring capacity. A
    /// restored setup must serialize to the same bytes and keep its capacity.
    /// Any other G1 length is a decode error: a raw SRS file would otherwise
    /// decode as a setup with the largest domain it can back, and two nodes
    /// that load the same file by different paths would build keys on
    /// different domains without any error.
    pub fn ring_setup_serialization<S: RingSuite>() {
        use ark_serialize::SerializationError;

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);
        let capacity = ring_setup.ring_context().max_ring_size();

        let mut bytes = Vec::new();
        ring_setup.serialize_uncompressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), ring_setup.uncompressed_size());
        let restored = RingSetup::<S>::deserialize_uncompressed_unchecked(&bytes[..]).unwrap();
        let mut restored_bytes = Vec::new();
        restored
            .serialize_uncompressed(&mut restored_bytes)
            .unwrap();
        assert_eq!(bytes, restored_bytes);
        assert_eq!(restored.ring_context().max_ring_size(), capacity);

        let decode = |pcs_params: &PcsParams<S>| {
            let mut buf = Vec::new();
            pcs_params.serialize_uncompressed(&mut buf).unwrap();
            RingSetup::<S>::deserialize_uncompressed_unchecked(&buf[..])
        };

        // Below the smallest domain (a panic once), the domain that holds no
        // key (a setup with capacity 0 once, on Jubjub), one power off, and
        // the power of two of an untrimmed SRS file (a setup with its own
        // domain once).
        let g1_powers = ring_setup.pcs_params.powers_in_g1.len();
        let g1_power = ring_setup.pcs_params.powers_in_g1[0];
        for g1_len in [
            0,
            1,
            3,
            4,
            100,
            3 * piop_overhead::<S>() + 1,
            g1_powers - 1,
            g1_powers + 1,
            g1_powers.next_power_of_two(),
            2 * g1_powers,
        ] {
            let mut wrong = ring_setup.pcs_params.clone();
            wrong.powers_in_g1.resize(g1_len, g1_power);
            assert!(
                matches!(decode(&wrong), Err(SerializationError::InvalidData)),
                "g1 powers = {g1_len}"
            );
        }

        let mut short = ring_setup.pcs_params.clone();
        short.powers_in_g2.truncate(1);
        assert!(matches!(
            decode(&short),
            Err(SerializationError::InvalidData)
        ));
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

        // Built-in SW suites place the base outside the prime order subgroup,
        // built-in TE suites inside it.
        let in_prime_subgroup = <AffinePoint<S> as FindAccumulatorBase<S>>::IN_PRIME_ORDER_SUBGROUP;
        assert!(S::ACCUMULATOR_BASE.check(in_prime_subgroup).is_ok());
    }

    #[allow(unused)]
    pub fn verifier_key_from_commitment<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let mut pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
        let prover_idx = 3;
        pks[prover_idx] = public.0;

        let prover_key = ring_setup.prover_key(&pks).unwrap();
        let prover = ring_setup
            .ring_context()
            .ring_prover(prover_key, prover_idx);
        let item = TestItem::<S>::new(&secret, &prover, rng);

        let commitment = ring_setup.verifier_key(&pks).unwrap().commitment();

        // Round-trip the params to mimic a verifier-only user holding just
        // the serialized params, the ring commitment and the ring size.
        let mut buf = Vec::new();
        ring_setup
            .pcs_verifier_params()
            .serialize_compressed(&mut buf)
            .unwrap();
        let pcs_params = PcsVerifierParams::<S>::deserialize_compressed(&buf[..]).unwrap();

        let ring_ctx = RingContext::<S>::new(TEST_RING_SIZE);
        let verifier_key = super::verifier_key_from_commitment::<S>(commitment, pcs_params);
        let verifier = ring_ctx.ring_verifier(verifier_key);
        assert!(Public::verify(item.io, &item.ad, &item.proof, &verifier).is_ok());
    }

    #[allow(unused)]
    pub fn verifier_key_builder<S: RingSuite>() {
        use crate::testing::{random_val, random_vec};

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(common::random_val(Some(rng)));
        let io = secret.vrf_io(input);

        let ring_ctx = ring_setup.ring_context();
        let ring_size = ring_ctx.max_ring_size();
        let prover_idx = random_val::<usize>(Some(rng)) % ring_size;
        let mut pks = random_vec::<AffinePoint<S>>(ring_size, Some(rng));
        pks[prover_idx] = public.0;

        let prover_key = ring_setup.prover_key(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);
        let proof = secret.prove(io, b"foo", &prover);

        // Incremental ring verifier key construction
        let (mut vk_builder, lookup) = ring_setup.verifier_key_builder();
        assert_eq!(vk_builder.free_slots(), pks.len());
        assert_eq!(
            vk_builder.pcs_verifier_params(),
            ring_setup.pcs_verifier_params()
        );

        let extra_pk = random_val::<AffinePoint<S>>(Some(rng));
        assert_eq!(
            vk_builder.append(&[extra_pk], |_| None).unwrap_err(),
            Error::SrsLookupFailed
        );

        while !pks.is_empty() {
            let chunk_len = 1 + random_val::<usize>(Some(rng)) % 5;
            let chunk = pks.drain(..pks.len().min(chunk_len)).collect::<Vec<_>>();
            vk_builder.append(&chunk[..], &lookup).unwrap();
            assert_eq!(vk_builder.free_slots(), pks.len());
        }
        // No more space left; `free_slots` reports the remaining capacity.
        let extra_pk = random_val::<AffinePoint<S>>(Some(rng));
        assert_eq!(
            vk_builder.append(&[extra_pk], &lookup).unwrap_err(),
            Error::RingCapacityExceeded
        );
        assert_eq!(vk_builder.free_slots(), 0);
        let verifier_key = vk_builder.finalize();
        let verifier = ring_ctx.ring_verifier(verifier_key);
        let result = Public::verify(io, b"foo", &proof, &verifier);
        assert!(result.is_ok());
    }

    /// Downstream types that derive `Debug` need `Proof<S>: Debug`. The
    /// backend ring proof type has no `Debug`, so the impl is manual and a
    /// refactor can drop it without any other test noticing.
    #[allow(unused)]
    pub fn proof_is_debug<S: RingSuite + core::fmt::Debug>() {
        fn assert_debug<T: core::fmt::Debug>() {}
        assert_debug::<Proof<S>>();
    }

    pub fn domain_size_conversions<S: RingSuite>() {
        let overhead = piop_overhead::<S>();

        for ring_size in [1, 10, 200, 300, 500, 1000, 2000, 10000] {
            let piop_dom_size = piop_domain_size::<S>(ring_size);
            let pcs_dom_size = pcs_domain_size::<S>(ring_size);
            let max_ring_size = max_ring_size_from_piop_domain_size::<S>(piop_dom_size).unwrap();

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
            let piop_dom_rt = piop_domain_size_from_pcs_domain_size(pcs_dom_size).unwrap();
            assert_eq!(piop_dom_size, piop_dom_rt);
            let pcs_dom_rt = pcs_domain_size_from_piop_domain_size(piop_dom_rt);
            assert_eq!(pcs_dom_size, pcs_dom_rt);

            let max_ring_from_pcs = max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size).unwrap();
            assert_eq!(max_ring_size, max_ring_from_pcs);

            // max_ring + 1 should require a larger piop domain
            let next_piop = piop_domain_size::<S>(max_ring_size + 1);
            assert!(next_piop > piop_dom_size,);
            assert!(next_piop.is_power_of_two());
        }

        // Test inverse with arbitrary PCS values (not necessarily properly constructed)
        // The inverse function should recover the largest valid piop that fits
        for pcs_dom_size in [1 << 11, 1 << 12, 1 << 14, 1 << 16] {
            let piop_dom = piop_domain_size_from_pcs_domain_size(pcs_dom_size).unwrap();
            let max_ring = max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size).unwrap();

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

        // A domain holds at least one key. At or below the overhead nothing
        // fits: `None`, so no context or setup has capacity 0.
        assert_eq!(max_ring_size_from_piop_domain_size::<S>(overhead - 1), None);
        assert_eq!(max_ring_size_from_piop_domain_size::<S>(overhead), None);
        assert_eq!(
            max_ring_size_from_piop_domain_size::<S>(overhead + 1),
            Some(1)
        );
        for pcs_dom_size in [0, 1, 2, 3] {
            assert_eq!(piop_domain_size_from_pcs_domain_size(pcs_dom_size), None);
        }
        assert_eq!(piop_domain_size_from_pcs_domain_size(4), Some(1));
        let min_pcs_dom_size = pcs_domain_size::<S>(0);
        assert_eq!(
            max_ring_size_from_pcs_domain_size::<S>(min_pcs_dom_size - 1),
            None
        );
        assert_eq!(
            max_ring_size_from_pcs_domain_size::<S>(min_pcs_dom_size),
            Some(dom_utils::max_ring_size::<S>(0))
        );

        // A ring size of 0 counts as 1: the context holds at least one key.
        assert_eq!(piop_domain_size::<S>(0), piop_domain_size::<S>(1));
        assert!(dom_utils::max_ring_size::<S>(0) >= 1);
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
                fn proof_encoding_is_canonical() {
                    $crate::ring::testing::proof_encoding_is_canonical::<$suite>()
                }

                #[test]
                fn prove_verify_multi() {
                    $crate::ring::testing::prove_verify_multi::<$suite>()
                }

                #[test]
                fn prove_verify_batch() {
                    $crate::ring::testing::prove_verify_batch::<$suite>()
                }

                #[test]
                fn ring_size_exceeded() {
                    $crate::ring::testing::ring_size_exceeded::<$suite>()
                }

                #[test]
                fn off_curve_pairing_point_rejected() {
                    $crate::ring::testing::off_curve_pairing_point_rejected::<$suite>()
                }

                #[test]
                fn identity_in_ring_rejected() {
                    $crate::ring::testing::identity_in_ring_rejected::<$suite>()
                }

                #[test]
                fn ring_setup_serialization() {
                    $crate::ring::testing::ring_setup_serialization::<$suite>()
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
                fn verifier_key_from_commitment() {
                    $crate::ring::testing::verifier_key_from_commitment::<$suite>()
                }

                #[test]
                fn domain_size_conversions() {
                    $crate::ring::testing::domain_size_conversions::<$suite>()
                }

                #[test]
                fn proof_is_debug() {
                    $crate::ring::testing::proof_is_debug::<$suite>()
                }

                $crate::test_vectors!($crate::ring::testing::TestVector<$suite>);
            }
        };
    }

    pub trait RingSuiteExt: RingSuite + crate::testing::SuiteExt {
        const SRS_FILE: &str;

        fn ring_setup() -> &'static RingSetup<Self>;

        #[allow(unused)]
        fn load_ring_setup() -> RingSetup<Self> {
            use ark_serialize::CanonicalDeserialize;
            use std::{fs::File, io::Read};
            let mut file = File::open(Self::SRS_FILE).unwrap();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).unwrap();
            let pcs_params =
                PcsParams::<Self>::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
            RingSetup::from_pcs_params(crate::ring::testing::TEST_RING_SIZE, pcs_params).unwrap()
        }

        #[allow(unused)]
        fn write_ring_setup(ring_setup: &RingSetup<Self>) {
            use ark_serialize::CanonicalSerialize;
            use std::{fs::File, io::Write};
            let mut file = File::create(Self::SRS_FILE).unwrap();
            let mut buf = Vec::new();
            ring_setup
                .pcs_params
                .serialize_uncompressed(&mut buf)
                .unwrap();
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
            S::SUITE_NAME.to_string() + "_ring"
        }

        fn new(comment: &str, seed: &[u8; 32], alpha: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let pedersen = pedersen::testing::TestVector::new(comment, seed, alpha, ad);

            let secret = Secret::<S>::from_scalar(pedersen.base.sk);
            let public = secret.public();

            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(pedersen.base.h),
                output: Output::from_affine_unchecked(pedersen.base.gamma),
            };

            let ring_setup = <S as RingSuiteExt>::ring_setup();

            use ark_std::rand::SeedableRng;
            let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42; 32]);
            let prover_idx = 3;
            let mut ring_pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
            ring_pks[prover_idx] = public.0;

            // Blinding is disabled to make the proof reproducible
            let ring_ctx = RingContext::<S>::new_without_blinding(TEST_RING_SIZE);
            let prover_key = ring_setup.prover_key(&ring_pks).unwrap();
            let prover = ring_ctx.into_ring_prover(prover_key, prover_idx);
            let proof = secret.prove(io, ad, &prover);

            let verifier_key = ring_setup.verifier_key(&ring_pks).unwrap();
            let ring_pks_com = verifier_key.commitment();

            {
                // Just in case...
                let mut p = (Vec::new(), Vec::new());
                pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

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

            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(self.pedersen.base.h),
                output: Output::from_affine_unchecked(self.pedersen.base.gamma),
            };
            let secret = Secret::from_scalar(self.pedersen.base.sk);
            let public = secret.public();
            assert_eq!(public.0, self.pedersen.base.pk);

            let ring_setup = <S as RingSuiteExt>::ring_setup();

            let prover_idx = self.ring_pks.iter().position(|&pk| pk == public.0).unwrap();

            // Blinding is disabled to reproduce the exact proof in the vector
            let ring_ctx = RingContext::<S>::new_without_blinding(TEST_RING_SIZE);
            let prover_key = ring_setup.prover_key(&self.ring_pks).unwrap();
            let prover = ring_ctx.ring_prover(prover_key, prover_idx);

            let verifier_key = ring_setup.verifier_key(&self.ring_pks).unwrap();
            let verifier = ring_ctx.ring_verifier(verifier_key);

            let proof = secret.prove(io, &self.pedersen.base.ad, &prover);

            {
                // Check if Pedersen proof matches
                let mut p = (Vec::new(), Vec::new());
                self.pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            {
                // Check if the (deterministic) ring proof matches
                let mut p = (Vec::new(), Vec::new());
                self.ring_proof.serialize_compressed(&mut p.0).unwrap();
                proof.ring_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            assert!(Public::verify(io, &self.pedersen.base.ad, &proof, &verifier).is_ok());
        }
    }
}
