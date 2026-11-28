//! # Ring VRF
//!
//! Pedersen VRF plus a ring proof after
//! [CSSV22](https://eprint.iacr.org/2022/1205): the committed key is in the
//! ring, and the proof does not show which key it is. Needs the `ring` feature.
//!
//! The ring prover draws its blinding from the OS random source, and `prove`
//! panics where `getrandom` has no source. [`RingContext::new_without_blinding`]
//! does not draw for the ring proof, and its proofs are not zero knowledge.
//!
//! ## Setup
//!
//! Build the [`RingSetup`] from the SRS of a trusted setup ceremony with
//! [`RingSetup::from_pcs_params`]. The repository has the Zcash ceremony SRS in
//! `data/srs/`. [`RingSetup::from_seed_insecure`] and
//! [`RingSetup::from_rand_insecure`] know the trapdoor and are for tests only.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::ring::Proof;
//!
//! const RING_SIZE: usize = 100;
//! let prover_key_index = 3;
//!
//! // Create a ring of public keys
//! let mut ring = (0..RING_SIZE)
//!     .map(|i| {
//!         let mut seed = [0u8; 32];
//!         seed[..8].copy_from_slice(&i.to_le_bytes());
//!         SecretKey::from_seed(seed).public_key()
//!     })
//!     .collect::<Vec<_>>();
//! ring[prover_key_index] = pk;
//!
//! // Initialize ring parameters
//! let ring_setup = RingSetup::from_seed_insecure(RING_SIZE, [0x42; 32]);
//! let ring_ctx = ring_setup.ring_context();
//!
//! // Proving
//! let prover_key = ring_setup.prover_key(&ring).unwrap();
//! let prover = ring_ctx.ring_prover(prover_key, prover_key_index);
//! let io = secret.io_pair(input);
//! let proof = Proof::prove(io, b"aux data", &secret, &prover);
//!
//! // Verification
//! let verifier_key = ring_setup.verifier_key(&ring).unwrap();
//! let verifier = ring_ctx.ring_verifier(verifier_key);
//! let res = proof.verify(io, b"aux data", &verifier);
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
use ark_std::{borrow::Borrow, ops::Range};
use core::cell::Cell;
use pedersen::{PedersenSuite, Proof as PedersenProof};
use utils::canonical::CanonicalDeserializeStrict;
use utils::common::ProjectiveZ;
use utils::te_sw_map::TEMapping;
use w3f_ring_proof as ring_proof;

/// Seed hashed to curve to produce [`RingSuite::ACCUMULATOR_BASE`] in built-in suites.
pub const ACCUMULATOR_BASE_SEED: &[u8] = b"ring-accumulator";

/// Seed hashed to curve to produce [`RingSuite::PADDING`] in built-in suites.
pub const PADDING_SEED: &[u8] = b"ring-padding";

/// Suites with Ring VRF. The bounds on `Affine` come from the ring proof
/// backend.
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

    /// Accumulator base. Nobody may know its discrete log to the generator, and
    /// it must not be the identity. It need not be in the prime-order subgroup.
    ///
    /// The built-in twisted Edwards suites hash [`ACCUMULATOR_BASE_SEED`] to the
    /// curve. The short Weierstrass Bandersnatch suite adds a fixed point
    /// outside the subgroup to the hashed point.
    const ACCUMULATOR_BASE: AffinePoint<Self>;

    /// Padding point. Nobody may know its discrete log to the generator, so it
    /// can replace any key in a ring. The built-in suites hash [`PADDING_SEED`]
    /// to the curve.
    const PADDING: AffinePoint<Self>;
}

/// KZG Polynomial Commitment Scheme.
pub type Kzg<S> = ring_proof::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG commitment.
pub type PcsCommitment<S> = <Kzg<S> as ring_proof::pcs::PCS<BaseField<S>>>::C;

/// KZG parameters: the powers-of-tau SRS.
pub type PcsParams<S> = ring_proof::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

/// PCS parameters of the verifier: a few SRS points, independent of the ring
/// size. With a [`RingCommitment`], they give a [`RingVerifierKey`] (see
/// [`verifier_key_from_commitment`]). See [`RingVerifierKey`] for the
/// uncompressed decoder.
pub type PcsVerifierParams<S> = <PcsParams<S> as ring_proof::pcs::PcsParams>::RVK;

/// Polynomial IOP parameters of the ring proof.
pub type PiopParams<S> = ring_proof::PiopParams<TEAffine<CurveConfig<S>>>;

/// Commitment to the ring keys. See [`RingVerifierKey`] for the uncompressed
/// decoder.
pub type RingCommitment<S> = ring_proof::FixedColumnsCommitted<BaseField<S>, PcsCommitment<S>>;

/// Ring prover key.
pub type RingProverKey<S> = ring_proof::ProverKey<BaseField<S>, Kzg<S>, TEAffine<CurveConfig<S>>>;

/// Ring verifier key.
///
/// The backend decoder does not check that an uncompressed BLS12-381 point is
/// on the curve. After an uncompressed decode of untrusted bytes, call
/// `Valid::check`, or use the compressed form. The same holds for
/// [`RingCommitment`] and [`PcsVerifierParams`].
pub type RingVerifierKey<S> = ring_proof::VerifierKey<BaseField<S>, Kzg<S>>;

/// Ring prover.
pub type RingProver<S> = ring_proof::ring_prover::RingProver<BaseField<S>, Kzg<S>, CurveConfig<S>>;

/// Ring verifier.
pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, Kzg<S>, CurveConfig<S>>;

/// KZG batch verifier for the ring proofs of one or more rings with the same
/// SRS: one pairing check for all.
pub type RingBatchVerifier<S> = ring_proof::multi_ring_batch_verifier::BatchVerifier<
    <S as RingSuite>::Pairing,
    ring_proof::ArkTranscript,
>;

/// Ring membership proof of the backend, the second part of a [`Proof`].
pub type RingBareProof<S> = ring_proof::RingProof<BaseField<S>, Kzg<S>>;

/// Ring VRF proof: a Pedersen VRF proof, and a proof that its key commitment
/// `Yb` is in the ring.
///
/// Decoding follows the rules in [`PointWrapper`].
#[derive(Clone, CanonicalSerialize)]
pub struct Proof<S: RingSuite> {
    pub(crate) pedersen_proof: PedersenProof<S>,
    pub(crate) ring_proof: RingBareProof<S>,
}

impl<S: RingSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let pedersen_proof =
            PedersenProof::<S>::deserialize_with_mode(&mut reader, compress, validate)?;
        let ring_proof = RingBareProof::<S>::deserialize_strict(&mut reader, compress, validate)?;
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

impl<S: RingSuite> Proof<S> {
    /// Prove the VRF I/O pairs `ios` with the additional data `ad`.
    ///
    /// `ring_prover` must be built for the ring and for the position of the key
    /// of `secret` in it (see [`RingContext::ring_prover`]).
    pub fn prove(
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        secret: &SecretKey<S>,
        ring_prover: &RingProver<S>,
    ) -> Self {
        let (pedersen_proof, secret_blinding) = PedersenProof::prove(ios, ad, secret);
        let ring_proof = ring_prover.prove(*secret_blinding.expose_secret());
        Proof {
            pedersen_proof,
            ring_proof,
        }
    }

    /// Verify the proof for the VRF I/O pairs `ios` and the additional data `ad`.
    /// `verifier` must be built for the ring (see [`RingContext::ring_verifier`]).
    ///
    /// Returns `Error::InvalidData` if the key commitment or a point of `ios` is
    /// the identity, or if the ring backend cannot take the key commitment (see
    /// [`BatchItem::new`]), and `Error::VerificationFailure` if the proof is not
    /// valid. Subgroup membership is not checked (see [`PointWrapper`]).
    pub fn verify(
        &self,
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error> {
        self.pedersen_proof.verify(ios, ad)?;
        let key_commitment = self.backend_key_commitment()?;
        if !verifier.verify(self.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }

    /// The ring backend adds the key commitment to the accumulator seed with
    /// an incomplete formula, and panics if the sum has no affine form.
    ///
    /// The backend checks this itself after
    /// <https://github.com/paritytech/ring-proof/pull/104>. After that release,
    /// remove the check here and map the `None` of the backend `BatchItem::new`
    /// to `Error::InvalidData`. Single verify then returns
    /// `Error::VerificationFailure`, so update the docs of `verify`.
    fn backend_key_commitment(&self) -> Result<TEAffine<CurveConfig<S>>, Error> {
        let key_commitment = self
            .pedersen_proof
            .key_commitment()
            .into_te()
            .ok_or(Error::InvalidData)?;
        let seed = S::ACCUMULATOR_BASE
            .into_te()
            .expect("ACCUMULATOR_BASE must not be identity");
        if !(seed + key_commitment).has_affine_form() {
            return Err(Error::InvalidData);
        }
        Ok(key_commitment)
    }
}

impl<S: RingSuite> SecretKey<S> {
    /// Generate a Ring VRF proof. Same as [`Proof::prove`].
    pub fn prove_ring(
        &self,
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        ring_prover: &RingProver<S>,
    ) -> Proof<S> {
        Proof::prove(ios, ad, self, ring_prover)
    }
}

/// Ring proof context: the PIOP parameters, without the SRS.
///
/// Build it from a ring size with [`RingContext::new`], or take it from a
/// [`RingSetup`] with [`RingSetup::ring_context`].
#[derive(Clone)]
pub struct RingContext<S: RingSuite> {
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
    ///
    /// # Panics
    ///
    /// Panics if no evaluation domain holds `min_ring_size` keys.
    pub fn new(min_ring_size: usize) -> Self {
        Self::construct(min_ring_size, true)
    }

    /// Context whose provers make proofs with no blinding. The proofs of a key
    /// that is not hedged are deterministic.
    ///
    /// The proofs are not zero knowledge, but verifiers with a regular context
    /// of the same ring size accept them. Use it for test vectors.
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

    /// Maximum ring size of this context.
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
    /// from a setup with the domain of this context: with a key of another
    /// domain, proving panics in the ring backend.
    pub fn ring_prover(&self, prover_key: RingProverKey<S>, key_index: usize) -> RingProver<S> {
        self.clone().into_ring_prover(prover_key, key_index)
    }

    /// Create a verifier instance from a verifier key.
    pub fn ring_verifier(&self, verifier_key: RingVerifierKey<S>) -> RingVerifier<S> {
        self.clone().into_ring_verifier(verifier_key)
    }

    /// Same as [`Self::ring_prover`], but consumes the context.
    pub fn into_ring_prover(self, prover_key: RingProverKey<S>, key_index: usize) -> RingProver<S> {
        let key_index = wrap_key_index(key_index, self.max_ring_size());
        RingProver::<S>::init(
            prover_key,
            self.piop_params,
            key_index,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Same as [`Self::ring_verifier`], but consumes the context.
    pub fn into_ring_verifier(self, verifier_key: RingVerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop_params,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }
}

/// Ring proof setup: the KZG parameters and the [`RingContext`].
///
/// The encoding is the SRS trimmed to the domain, so its G1 length gives the
/// ring capacity, and the decoder accepts only that length. A raw SRS file is
/// not a setup: decode it as [`PcsParams`] and call [`Self::from_pcs_params`].
#[derive(Clone)]
pub struct RingSetup<S: RingSuite> {
    pcs_params: PcsParams<S>,
    ring_ctx: RingContext<S>,
}

/// At most `capacity` ring members as twisted Edwards points. The backend
/// asserts on the identity, so this rejects it.
fn ring_members_te<S: RingSuite, P: Borrow<PublicKey<S>>>(
    pks: impl IntoIterator<Item = P>,
    capacity: usize,
) -> Result<Vec<TEAffine<CurveConfig<S>>>, Error> {
    let pks = pks.into_iter();
    let mut members = Vec::with_capacity(pks.size_hint().0.min(capacity));
    for pk in pks {
        if members.len() == capacity {
            return Err(Error::RingCapacityExceeded);
        }
        let point = pk.borrow().0;
        if point.is_zero() {
            return Err(Error::InvalidData);
        }
        members.push(point.into_te().ok_or(Error::InvalidData)?);
    }
    Ok(members)
}

impl<S: RingSuite> PublicKey<S> {
    /// [`RingSuite::PADDING`] as a ring member, for example in place of a
    /// removed key.
    pub fn padding() -> Self {
        Self::from_affine_unchecked(S::PADDING)
    }
}

impl<S: RingSuite> RingSetup<S> {
    /// Setup for at least `min_ring_size` keys, from `seed`.
    ///
    /// # Insecure
    ///
    /// Anybody who knows the seed knows the KZG trapdoor and can forge ring
    /// proofs. Use it for tests only.
    pub fn from_seed_insecure(min_ring_size: usize, seed: [u8; 32]) -> Self {
        let mut t = S::Transcript::new(S::SUITE_ID);
        t.absorb_raw(&seed);
        let mut rng = t.to_rng();
        Self::from_rand_insecure(min_ring_size, &mut rng)
    }

    /// Random setup for at least `min_ring_size` keys.
    ///
    /// # Insecure
    ///
    /// The party that runs it knows the KZG trapdoor and can forge ring proofs.
    /// Use it for tests only.
    pub fn from_rand_insecure(min_ring_size: usize, rng: &mut impl ark_std::rand::RngCore) -> Self {
        use ring_proof::pcs::PCS;
        let max_degree = pcs_domain_size::<S>(min_ring_size) - 1;
        let pcs_params = Kzg::<S>::setup(max_degree, rng);
        Self::from_pcs_params(min_ring_size, pcs_params).expect("PCS params is correct")
    }

    /// Setup for at least `min_ring_size` keys from a KZG SRS, trimmed to the
    /// domain. Returns `Error::RingCapacityExceeded` if the SRS is too short.
    ///
    /// `pcs_params` must come from a trusted setup ceremony: anybody who knows
    /// the trapdoor can forge ring proofs. The Zcash ceremony SRS in
    /// `data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin` holds 1791
    /// Bandersnatch or 1792 Jubjub keys.
    pub fn from_pcs_params(
        min_ring_size: usize,
        mut pcs_params: PcsParams<S>,
    ) -> Result<Self, Error> {
        // The capacity comes from the SRS length, so a huge `min_ring_size`
        // never reaches the domain arithmetic.
        let capacity = max_ring_size_from_pcs_domain_size::<S>(pcs_params.powers_in_g1.len());
        if !capacity.is_some_and(|capacity| capacity >= min_ring_size)
            || pcs_params.powers_in_g2.len() < 2
        {
            return Err(Error::RingCapacityExceeded);
        }
        pcs_params
            .powers_in_g1
            .truncate(pcs_domain_size::<S>(min_ring_size));
        pcs_params.powers_in_g2.truncate(2);

        Ok(Self {
            pcs_params,
            ring_ctx: RingContext::new(min_ring_size),
        })
    }

    /// Prover key and verifier key for the ring `pks`, in one pass. Calling
    /// [`Self::prover_key`] and [`Self::verifier_key`] costs twice as much.
    ///
    /// `pks` iterates over keys or key references, for example `&ring` for a
    /// `Vec<PublicKey<S>>`. Subgroup membership is not checked (see
    /// [`PointWrapper`]).
    ///
    /// Each key must come with a proof of possession of its secret key, which
    /// this function does not check. For some keys with no known secret, such
    /// as [`RingSuite::ACCUMULATOR_BASE`], the ring backend leaves one
    /// coordinate of its accumulator free, and the soundness argument of the
    /// ring proof does not hold.
    ///
    /// Returns `Error::RingCapacityExceeded` if `pks` is larger than the ring
    /// capacity, and `Error::InvalidData` if a key is the identity or has no
    /// twisted Edwards form.
    pub fn keys<P: Borrow<PublicKey<S>>>(
        &self,
        pks: impl IntoIterator<Item = P>,
    ) -> Result<(RingProverKey<S>, RingVerifierKey<S>), Error> {
        let pks = ring_members_te::<S, P>(pks, self.ring_ctx.max_ring_size())?;
        Ok(ring_proof::index(
            &self.pcs_params,
            &self.ring_ctx.piop_params,
            &pks,
        ))
    }

    /// Prover key for the ring `pks`. Same inputs and errors as [`Self::keys`].
    pub fn prover_key<P: Borrow<PublicKey<S>>>(
        &self,
        pks: impl IntoIterator<Item = P>,
    ) -> Result<RingProverKey<S>, Error> {
        Ok(self.keys(pks)?.0)
    }

    /// Verifier key for the ring `pks`. Same inputs and errors as [`Self::keys`].
    pub fn verifier_key<P: Borrow<PublicKey<S>>>(
        &self,
        pks: impl IntoIterator<Item = P>,
    ) -> Result<RingVerifierKey<S>, Error> {
        Ok(self.keys(pks)?.1)
    }

    /// Verifier key from a ring commitment (see [`RingVerifierKey::commitment`]).
    pub fn verifier_key_from_commitment(
        &self,
        commitment: RingCommitment<S>,
    ) -> RingVerifierKey<S> {
        verifier_key_from_commitment::<S>(commitment, self.pcs_verifier_params())
    }

    /// PCS parameters of the verifier (see [`PcsVerifierParams`]).
    pub fn pcs_verifier_params(&self) -> PcsVerifierParams<S> {
        use ring_proof::pcs::PcsParams;
        self.pcs_params.raw_vk()
    }

    /// Builder for a verifier key that takes the keys in parts.
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

    /// Get a reference to the [`RingContext`].
    pub fn ring_context(&self) -> &RingContext<S> {
        &self.ring_ctx
    }
}

/// Verifier key from a ring commitment and the PCS verifier parameters, with
/// no SRS.
///
/// `pcs_params` must come from the trusted setup of the commitment. The decoder
/// cannot tell a valid setup from a malicious one, so take the parameters from
/// a trusted source, not from the proof data.
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

/// SRS in Lagrangian form, for the [`VerifierKeyBuilder`]. See
/// `PcsParams::ck_with_lagrangian()`.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingBuilderPcsParams<S: RingSuite>(pub Vec<G1Affine<S>>);

type PartialRingCommitment<S> =
    ring_proof::ring::Ring<BaseField<S>, <S as RingSuite>::Pairing, TEAffine<CurveConfig<S>>>;

/// Builder for a ring verifier key that takes the keys in parts, for large rings
/// or small memory.
///
/// An encoded builder holds the ring commitment, so it defines the ring like a
/// verifier key does: load it only from a trusted source. The decoder rejects a
/// padding point other than [`RingSuite::PADDING`] and a capacity that no PIOP
/// domain gives, but it cannot check the commitment.
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
        // A capacity is a power-of-two domain minus the overhead, checked
        // without the overflow that rounding up a hostile value would cause.
        let is_capacity = partial
            .max_keys
            .checked_add(dom_utils::piop_overhead::<S>())
            .is_some_and(usize::is_power_of_two);
        if !is_capacity
            || partial.curr_keys > partial.max_keys
            || S::PADDING.into_te() != Some(partial.padding)
        {
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

/// Access to SRS points in Lagrangian form.
pub trait SrsLookup<S: RingSuite> {
    /// SRS points of `range`, or `None` if the range is out of bounds. A result
    /// with a length other than `range.len()` counts as a failed lookup.
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

/// What the backend expects from its SRS lookup closure.
type SrsSegment<S> = Result<Vec<G1Affine<S>>, ()>;

/// The backend asks its lookup closure for one range, once, and panics on an
/// error. So fetch the range first with the fallible [`SrsLookup`], and give the
/// backend a closure that serves only that range, once.
fn prefetched_lookup<S: RingSuite>(
    lookup: impl SrsLookup<S>,
    range: Range<usize>,
) -> Result<impl Fn(Range<usize>) -> SrsSegment<S>, Error> {
    let points = lookup
        .lookup(range.clone())
        .filter(|points| points.len() == range.len())
        .ok_or(Error::SrsLookupFailed)?;
    let points = Cell::new(Some(points));
    Ok(move |asked| {
        if asked != range {
            return Err(());
        }
        points.take().ok_or(())
    })
}

impl<S: RingSuite> VerifierKeyBuilder<S> {
    /// Empty builder. Returns `Error::SrsLookupFailed` if `lookup` does not cover
    /// `max_ring_size..piop_domain_size`, the part of the SRS after the keys.
    pub fn new(ring_setup: &RingSetup<S>, lookup: impl SrsLookup<S>) -> Result<Self, Error> {
        let keys = ring_setup.ring_ctx.max_ring_size();
        let srs = prefetched_lookup(lookup, keys..piop_domain_size::<S>(keys))?;
        let pcs_params = ring_setup.pcs_verifier_params();
        let partial = PartialRingCommitment::<S>::empty(
            &ring_setup.ring_ctx.piop_params,
            srs,
            pcs_params.g1.into_group(),
        );
        Ok(VerifierKeyBuilder {
            partial,
            pcs_params,
        })
    }

    /// Number of free key slots.
    #[inline(always)]
    pub fn free_slots(&self) -> usize {
        self.partial.max_keys - self.partial.curr_keys
    }

    /// Same as [`RingSetup::pcs_verifier_params`] of the setup of the builder.
    pub fn pcs_verifier_params(&self) -> PcsVerifierParams<S> {
        self.pcs_params.clone()
    }

    /// Add the keys `pks` (as for [`RingSetup::keys`]). On an error, no key is
    /// added.
    ///
    /// Returns `Error::RingCapacityExceeded` if the keys do not fit in
    /// [`Self::free_slots`], `Error::SrsLookupFailed` if the SRS lookup fails, and
    /// `Error::InvalidData` if a key is the identity or has no twisted Edwards
    /// form.
    pub fn append<P: Borrow<PublicKey<S>>>(
        &mut self,
        pks: impl IntoIterator<Item = P>,
        lookup: impl SrsLookup<S>,
    ) -> Result<(), Error> {
        let pks = ring_members_te::<S, P>(pks, self.free_slots())?;
        let srs = prefetched_lookup(
            lookup,
            self.partial.curr_keys..self.partial.curr_keys + pks.len(),
        )?;
        self.partial.append(&pks, srs);
        Ok(())
    }

    /// The verifier key of the keys added so far.
    pub fn finalize(self) -> RingVerifierKey<S> {
        RingVerifierKey::<S>::from_ring_and_kzg_vk(&self.partial, self.pcs_params)
    }
}

type RingProofBatchItem<S> =
    ring_proof::multi_ring_batch_verifier::BatchItem<<S as RingSuite>::Pairing>;

/// Ring VRF proof prepared for [`BatchVerifier`].
pub struct BatchItem<S: RingSuite> {
    ring: RingProofBatchItem<S>,
    pedersen: pedersen::BatchItem<S>,
}

impl<S: RingSuite> BatchItem<S> {
    /// Prepare a proof for batch verification. This is cheap and can run in
    /// parallel. `verifier` must be built for the ring of the proof.
    ///
    /// Returns `Error::InvalidData` if the ring backend cannot take the key
    /// commitment: it has no twisted Edwards form (for example the identity on
    /// a short Weierstrass suite), or its sum with
    /// [`RingSuite::ACCUMULATOR_BASE`] has no affine form.
    pub fn new(
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<Self, Error> {
        let key_commitment = proof.backend_key_commitment()?;
        let pedersen = pedersen::BatchItem::new(ios, ad, &proof.pedersen_proof);
        let ring = RingProofBatchItem::<S>::new(verifier, proof.ring_proof.clone(), key_commitment);
        Ok(Self { ring, pedersen })
    }
}

/// Batch verifier for Ring VRF proofs of one or more rings with the same SRS.
pub struct BatchVerifier<S: RingSuite> {
    ring_batch: RingBatchVerifier<S>,
    pedersen_batch: pedersen::BatchVerifier<S>,
}

impl<S: RingSuite> BatchVerifier<S> {
    /// Empty batch verifier with the KZG verifier key of `ring_verifier`. Each
    /// ring verifier with the same SRS can then go to [`Self::push`] or
    /// [`BatchItem::new`].
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

    /// Prepare and push a proof in one step. Returns the errors of
    /// [`BatchItem::new`].
    pub fn push(
        &mut self,
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error> {
        let item = BatchItem::new(ios, ad, proof, verifier)?;
        self.push_prepared(item);
        Ok(())
    }

    /// Verify all the proofs: one multi-scalar multiplication for the Pedersen
    /// proofs and one pairing check for the ring proofs.
    ///
    /// Returns `Error::InvalidData` if a key commitment or a point of an I/O
    /// pair is the identity, and `Error::VerificationFailure` if a proof is not
    /// valid. Subgroup membership is not checked (see [`PointWrapper`]).
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
        /// KZG parameters, the powers of tau SRS.
        #[allow(dead_code)]
        pub type PcsParams = $crate::ring::PcsParams<$suite>;
        /// KZG verifier parameters.
        #[allow(dead_code)]
        pub type PcsVerifierParams = $crate::ring::PcsVerifierParams<$suite>;
        /// PIOP parameters.
        #[allow(dead_code)]
        pub type PiopParams = $crate::ring::PiopParams<$suite>;
        /// Ring context.
        #[allow(dead_code)]
        pub type RingContext = $crate::ring::RingContext<$suite>;
        /// Ring setup.
        #[allow(dead_code)]
        pub type RingSetup = $crate::ring::RingSetup<$suite>;
        /// Ring prover key.
        #[allow(dead_code)]
        pub type RingProverKey = $crate::ring::RingProverKey<$suite>;
        /// Ring verifier key.
        #[allow(dead_code)]
        pub type RingVerifierKey = $crate::ring::RingVerifierKey<$suite>;
        /// Ring keys commitment.
        #[allow(dead_code)]
        pub type RingCommitment = $crate::ring::RingCommitment<$suite>;
        /// Ring prover.
        #[allow(dead_code)]
        pub type RingProver = $crate::ring::RingProver<$suite>;
        /// Ring verifier.
        #[allow(dead_code)]
        pub type RingVerifier = $crate::ring::RingVerifier<$suite>;
        /// Ring VRF proof.
        #[allow(dead_code)]
        pub type RingProof = $crate::ring::Proof<$suite>;
        /// Incremental ring verifier key builder.
        #[allow(dead_code)]
        pub type RingVerifierKeyBuilder = $crate::ring::VerifierKeyBuilder<$suite>;
        /// Ring VRF batch verification item.
        #[allow(dead_code)]
        pub type RingBatchItem = $crate::ring::BatchItem<$suite>;
        /// Ring VRF batch verifier.
        #[allow(dead_code)]
        pub type RingBatchVerifier = $crate::ring::BatchVerifier<$suite>;
    };
}

/// Ring and domain sizes.
///
/// - `min_ring_size`: the number of keys that the caller asks for.
/// - `max_ring_size`: the number of keys that the domain holds.
/// - `piop_domain_size`: the PIOP domain size.
/// - `pcs_domain_size`: the number of G1 points of the SRS.
///
/// ```text
/// piop_domain_size = (max(min_ring_size, 1) + PIOP_OVERHEAD).next_power_of_two()
/// pcs_domain_size  = 3 * piop_domain_size + 1
/// max_ring_size    = piop_domain_size - PIOP_OVERHEAD
/// PIOP_OVERHEAD    = 4 + MODULUS_BIT_SIZE
/// ```
///
/// The overhead holds 3 blinding rows, 1 row of the PIOP and the bits of the
/// blinding factor. With a 254-bit scalar, ring sizes 1 to 254 all give
/// `piop_domain_size = 512` and `pcs_domain_size = 1537`.
pub mod dom_utils {
    use super::*;

    /// Ring capacity of the domain for `min_ring_size` keys. It is at least
    /// `min_ring_size`.
    pub const fn max_ring_size<S: Suite>(min_ring_size: usize) -> usize {
        piop_domain_size::<S>(min_ring_size) - piop_overhead::<S>()
    }

    /// PIOP overhead (see the module docs).
    pub const fn piop_overhead<S: Suite>() -> usize {
        4 + ScalarField::<S>::MODULUS_BIT_SIZE as usize
    }

    /// PIOP domain size for `min_ring_size` keys. A `min_ring_size` of 0 counts
    /// as 1.
    ///
    /// # Panics
    ///
    /// Panics if the domain size does not fit in a `usize`.
    pub const fn piop_domain_size<S: Suite>(min_ring_size: usize) -> usize {
        let min_ring_size = if min_ring_size == 0 { 1 } else { min_ring_size };
        let domain_size = match min_ring_size.checked_add(piop_overhead::<S>()) {
            Some(size) => size.checked_next_power_of_two(),
            None => None,
        };
        domain_size.expect("PIOP domain size overflows usize")
    }

    /// Ring capacity of a PIOP domain, or `None` if the domain holds no key.
    pub const fn max_ring_size_from_piop_domain_size<S: Suite>(
        piop_domain_size: usize,
    ) -> Option<usize> {
        if piop_domain_size > piop_overhead::<S>() {
            Some(piop_domain_size - piop_overhead::<S>())
        } else {
            None
        }
    }

    /// PCS domain size for `min_ring_size` keys: the SRS G1 points of the prover.
    pub const fn pcs_domain_size<S: Suite>(min_ring_size: usize) -> usize {
        pcs_domain_size_from_piop_domain_size(piop_domain_size::<S>(min_ring_size))
    }

    /// PCS domain size of a PIOP domain: `3 * piop_domain_size + 1`.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit in a `usize`.
    pub const fn pcs_domain_size_from_piop_domain_size(piop_domain_size: usize) -> usize {
        let domain_size = match piop_domain_size.checked_mul(3) {
            Some(size) => size.checked_add(1),
            None => None,
        };
        domain_size.expect("PCS domain size overflows usize")
    }

    /// PIOP domain size of a PCS domain, rounded down to a power of two. Returns
    /// `None` if `pcs_domain_size` is below 4.
    pub const fn piop_domain_size_from_pcs_domain_size(pcs_domain_size: usize) -> Option<usize> {
        match (pcs_domain_size.saturating_sub(1) / 3).checked_ilog2() {
            Some(log2) => Some(1 << log2),
            None => None,
        }
    }

    /// Ring capacity of a PCS domain, or `None` if no domain fits.
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

    /// The domain of the ring vectors: |D| of spec section 5.
    pub const TEST_VECTOR_DOMAIN_SIZE: usize = 2048;

    const MAX_AD_LEN: usize = 100;

    /// The backend panics on a lookup error, so the closure must serve the
    /// prefetched range once and nothing else. A failed lookup, also one with
    /// the wrong number of points, must give an error up front.
    pub fn prefetched_lookup_serves_the_range_once<S: RingSuite>() {
        let points = vec![G1Affine::<S>::generator(); 4];
        let srs = prefetched_lookup::<S>(|_: Range<usize>| Some(points.clone()), 3..7).unwrap();
        assert_eq!(srs(2..6), Err(()));
        assert_eq!(srs(3..8), Err(()));
        assert_eq!(srs(3..7), Ok(points.clone()));
        assert_eq!(srs(3..7), Err(()));

        let failed = prefetched_lookup::<S>(|_: Range<usize>| None, 3..7).map(|_| ());
        assert!(matches!(failed, Err(Error::SrsLookupFailed)));

        for range in [3..6, 3..8] {
            let wrong_length =
                prefetched_lookup::<S>(|_: Range<usize>| Some(points.clone()), range);
            assert!(matches!(
                wrong_length.map(|_| ()),
                Err(Error::SrsLookupFailed)
            ));
        }
    }

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
        io: IoPair<S>,
        ad: Vec<u8>,
        proof: Proof<S>,
    }

    impl<S: RingSuite> TestItem<S> {
        fn new(
            secret: &SecretKey<S>,
            prover: &RingProver<S>,
            rng: &mut dyn ark_std::rand::RngCore,
        ) -> Self {
            let input = Input::from_affine_unchecked(common::random_val(Some(rng)));
            let io = secret.io_pair(input);
            let ad_len = common::random_val::<usize>(Some(rng)) % (MAX_AD_LEN + 1);
            let ad = common::random_vec(ad_len, Some(rng));
            let proof = secret.prove_ring(io, &ad, prover);
            Self { io, ad, proof }
        }
    }

    fn random_ring<S: RingSuite>(
        size: usize,
        rng: &mut dyn ark_std::rand::RngCore,
    ) -> Vec<PublicKey<S>> {
        common::random_vec::<AffinePoint<S>>(size, Some(rng))
            .into_iter()
            .map(PublicKey::from_affine_unchecked)
            .collect()
    }

    #[allow(unused)]
    pub fn prove_verify<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let pk = secret.public_key();

        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = pk;

        let ring_ctx = ring_setup.ring_context();
        let (prover_key, verifier_key) = ring_setup.keys(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);

        let item = TestItem::<S>::new(&secret, &prover, rng);

        let verifier = ring_ctx.ring_verifier(verifier_key);
        let res = item.proof.verify(item.io, &item.ad, &verifier);
        assert!(res.is_ok());
    }

    /// One proof must have one encoding. With no I/O pairs, `Ok` is the
    /// identity, which arkworks reads from several byte strings.
    pub fn proof_encoding_is_canonical<S: RingSuite>() {
        use ark_serialize::Compress;

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);
        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = secret.public_key();
        let ring_ctx = ring_setup.ring_context();
        let (prover_key, verifier_key) = ring_setup.keys(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);
        let verifier = ring_ctx.ring_verifier(verifier_key);

        let ios: [IoPair<S>; 0] = [];
        let proof = secret.prove_ring(ios, b"foo", &prover);
        assert!(proof.pedersen_proof.ok.is_zero());

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(decoded.verify(ios, b"foo", &verifier).is_ok());
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

        // BN254 ignores the sign flag of an uncompressed point. BLS12-381 has no
        // alias there.
        let mut bytes = Vec::new();
        proof.serialize_uncompressed(&mut bytes).unwrap();
        let decoded = Proof::<S>::deserialize_uncompressed(&bytes[..]).unwrap();
        assert!(decoded.verify(ios, b"foo", &verifier).is_ok());
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

    #[allow(unused)]
    pub fn prove_verify_multi<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let pk = secret.public_key();

        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = pk;

        let ring_ctx = ring_setup.ring_context();
        let (prover_key, verifier_key) = ring_setup.keys(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);

        let verifier = ring_ctx.ring_verifier(verifier_key);

        let mut ios: Vec<IoPair<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                secret.io_pair(input)
            })
            .collect();
        ios.push(IoPair {
            input: Input::from_affine_unchecked(S::Affine::generator()),
            output: Output::from_affine_unchecked(pk.0),
        });

        let proof = secret.prove_ring(&ios[..], b"bar", &prover);
        assert!(proof.verify(&ios[..], b"bar", &verifier).is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(proof.verify(&bad_ios[..], b"bar", &verifier).is_err());

        assert!(proof.verify(&ios[..], b"baz", &verifier).is_err());
    }

    #[allow(unused)]
    pub fn prove_verify_batch<S: RingSuite>() {
        use rayon::prelude::*;

        const BATCH_SIZE: usize = 3 * TEST_RING_SIZE;

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let pk = secret.public_key();

        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = pk;

        let ring_ctx = ring_setup.ring_context();
        let (prover_key, verifier_key) = ring_setup.keys(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);

        let batch: Vec<_> = (0..BATCH_SIZE)
            .into_par_iter()
            .map_init(ark_std::test_rng, |rng, _| {
                TestItem::<S>::new(&secret, &prover, rng)
            })
            .collect();

        let verifier = ring_ctx.ring_verifier(verifier_key);

        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let res = batch_verifier.verify();
        assert!(res.is_ok());

        for item in batch.iter() {
            batch_verifier
                .push(item.io, &item.ad, &item.proof, &verifier)
                .unwrap();
            let res = batch_verifier.verify();
            assert!(res.is_ok());
        }

        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let prepared: Vec<_> = batch
            .par_iter()
            .map(|item| BatchItem::<S>::new(item.io, &item.ad, &item.proof, &verifier).unwrap())
            .collect();
        prepared
            .into_iter()
            .for_each(|p| batch_verifier.push_prepared(p));
        assert!(batch_verifier.verify().is_ok());

        // A second ring with the same SRS, in the same batch.
        let mut pks_b = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx_b = 1;
        pks_b[prover_idx_b] = pk;
        let (prover_key_b, verifier_key_b) = ring_setup.keys(&pks_b).unwrap();
        let prover_b = ring_ctx.ring_prover(prover_key_b, prover_idx_b);
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
                .push(item.io, &item.ad, &item.proof, &verifier)
                .unwrap();
        }
        for item in batch_b.iter() {
            batch_verifier
                .push(item.io, &item.ad, &item.proof, &verifier_b)
                .unwrap();
        }
        batch_verifier.verify().expect("multi-ring batch verifies");

        // The batch must use the verifier of each item.
        let mut batch_verifier = BatchVerifier::<S>::new(&verifier);
        let item_b = &batch_b[0];
        batch_verifier
            .push(item_b.io, &item_b.ad, &item_b.proof, &verifier)
            .unwrap();
        assert!(
            batch_verifier.verify().is_err(),
            "ring-B proof must not verify against verifier_a"
        );
    }

    /// A ring that is too large is not malformed data: the caller fixes it with
    /// larger parameters.
    #[allow(unused)]
    pub fn ring_size_exceeded<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let max_ring_size = ring_setup.ring_context().max_ring_size();
        let pks = random_ring::<S>(max_ring_size + 1, rng);
        assert!(matches!(
            ring_setup.prover_key(&pks),
            Err(Error::RingCapacityExceeded)
        ));
        assert!(matches!(
            ring_setup.verifier_key(&pks),
            Err(Error::RingCapacityExceeded)
        ));
        assert!(matches!(
            ring_setup.keys(&pks),
            Err(Error::RingCapacityExceeded)
        ));

        // An endless iterator must end with an error, not fill the memory.
        let endless = core::iter::repeat(PublicKey::<S>::padding());
        assert!(matches!(
            ring_setup.keys(endless),
            Err(Error::RingCapacityExceeded)
        ));

        // Also when the domain size does not fit in a `usize`.
        for min_ring_size in [max_ring_size + 1, usize::MAX / 3 + 1, usize::MAX] {
            let pcs_params = ring_setup.pcs_params.clone();
            assert!(matches!(
                RingSetup::<S>::from_pcs_params(min_ring_size, pcs_params),
                Err(Error::RingCapacityExceeded)
            ));
        }
    }

    /// The domain arithmetic must not wrap to a small domain with a false
    /// capacity.
    pub fn huge_ring_size_panics<S: RingSuite>() {
        RingContext::<S>::new(usize::MAX);
    }

    /// The backend asserts on the identity, so each function that gives it keys
    /// must reject it first.
    pub fn identity_in_ring_rejected<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        pks[0] = PublicKey::from_affine_unchecked(AffinePoint::<S>::zero());

        assert!(matches!(
            ring_setup.prover_key(&pks),
            Err(Error::InvalidData)
        ));
        assert!(matches!(
            ring_setup.verifier_key(&pks),
            Err(Error::InvalidData)
        ));
        assert!(matches!(ring_setup.keys(&pks), Err(Error::InvalidData)));

        let (mut vk_builder, lookup) = ring_setup.verifier_key_builder();
        let free_slots = vk_builder.free_slots();
        assert_eq!(
            vk_builder.append(&pks, &lookup).unwrap_err(),
            Error::InvalidData
        );
        assert_eq!(vk_builder.free_slots(), free_slots);
    }

    /// The ring backend adds the key commitment to the accumulator seed with
    /// an incomplete formula, and panics if the sum has no affine form. A proof
    /// with such a key commitment must give an error.
    pub fn batch_rejects_key_commitment<S: RingSuite>(key_commitment: AffinePoint<S>) {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);
        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = secret.public_key();
        let ring_ctx = ring_setup.ring_context();
        let (prover_key, verifier_key) = ring_setup.keys(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);
        let verifier = ring_ctx.ring_verifier(verifier_key);

        let ios: [IoPair<S>; 0] = [];
        let mut proof = secret.prove_ring(ios, b"foo", &prover);
        proof.pedersen_proof.pk_com = key_commitment;

        assert!(matches!(
            BatchItem::new(ios, b"foo", &proof, &verifier),
            Err(Error::InvalidData)
        ));
        let mut batch_verifier = BatchVerifier::new(&verifier);
        assert_eq!(
            batch_verifier.push(ios, b"foo", &proof, &verifier),
            Err(Error::InvalidData)
        );
        assert!(proof.verify(ios, b"foo", &verifier).is_err());
    }

    /// With the seed `(xs, ys)`, the Z of the backend sum is
    /// `1 - (d * xs * ys * x * y)^2`. The point `(1, 1 / (d * xs * ys))` is off
    /// the curve, so only an unchecked decoder gives it, but it gives Z = 0 on
    /// every suite.
    pub fn exceptional_key_commitment_rejected<S: RingSuite>() {
        use ark_ff::{Field, One};

        let seed = S::ACCUMULATOR_BASE.into_te().unwrap();
        let d = <CurveConfig<S> as TECurveConfig>::COEFF_D;
        let y = (d * seed.x * seed.y).inverse().unwrap();
        let point = TEAffine::new_unchecked(BaseField::<S>::one(), y);
        batch_rejects_key_commitment::<S>(AffinePoint::<S>::from_te(point).unwrap());
    }

    /// Map `(x, y)` to `(u^2 x, u^3 y)`: off the curve, but the group law of an
    /// `a = 0` curve never reads `b`, so the subgroup test still passes.
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
    /// in a ring proof and in a verifier key builder.
    pub fn off_curve_pairing_point_rejected<S: RingSuite>()
    where
        G1Affine<S>: OffCurveAlias,
    {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);
        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = secret.public_key();
        let ring_ctx = ring_setup.ring_context();
        let prover = ring_ctx.ring_prover(ring_setup.prover_key(&pks).unwrap(), prover_idx);
        let input = Input::from_affine_unchecked(common::random_val(Some(rng)));
        let proof = secret.prove_ring(secret.io_pair(input), b"foo", &prover);

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

    /// A builder with another padding point or a capacity that no PIOP domain
    /// gives must not decode, also on the unchecked path. `append` would remove
    /// the wrong padding from each key, and `free_slots` would be false.
    pub fn builder_decode_rejects_foreign_ring_shape<S: RingSuiteExt + 'static>() {
        let (builder, _) = S::ring_setup().verifier_key_builder();
        let decode = |builder: &VerifierKeyBuilder<S>| {
            let mut bytes = Vec::new();
            builder.serialize_compressed(&mut bytes).unwrap();
            VerifierKeyBuilder::<S>::deserialize_compressed_unchecked(&bytes[..])
        };
        assert!(decode(&builder).is_ok());

        let mut foreign_padding = builder.clone();
        foreign_padding.partial.padding = S::BLINDING_BASE.into_te().unwrap();
        assert!(decode(&foreign_padding).is_err());

        // `usize::MAX` overflows when rounded up to a power of two.
        for max_keys in [builder.partial.max_keys + 1, usize::MAX] {
            let mut foreign_capacity = builder.clone();
            foreign_capacity.partial.max_keys = max_keys;
            assert!(decode(&foreign_capacity).is_err());
        }
    }

    /// The G1 length gives the capacity, so any other length must not decode.
    /// Otherwise a raw SRS file decodes as a setup of another domain.
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

        // Too short, the domain with no key, one power off, an untrimmed file.
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
        assert_eq!(S::PADDING, S::data_to_point(PADDING_SEED).unwrap());
        assert!(S::PADDING.check(true).is_ok());

        // The padding replaces keys, so it must be a valid `PublicKey`.
        assert!(ark_serialize::Valid::check(&PublicKey::<S>::padding()).is_ok());
        assert_eq!(PublicKey::<S>::padding().into_affine(), S::PADDING);
    }

    #[allow(unused)]
    pub fn accumulator_base_check<S: RingSuite>()
    where
        AffinePoint<S>: FindAccumulatorBase<S> + CheckPoint,
    {
        assert_eq!(
            S::ACCUMULATOR_BASE,
            AffinePoint::<S>::find_accumulator_base(ACCUMULATOR_BASE_SEED).unwrap()
        );

        // Outside the prime-order subgroup on SW suites, inside on TE suites.
        let in_prime_subgroup = <AffinePoint<S> as FindAccumulatorBase<S>>::IN_PRIME_ORDER_SUBGROUP;
        assert!(S::ACCUMULATOR_BASE.check(in_prime_subgroup).is_ok());
    }

    #[allow(unused)]
    pub fn verifier_key_from_commitment<S: RingSuite>() {
        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let pk = secret.public_key();

        let mut pks = random_ring::<S>(TEST_RING_SIZE, rng);
        let prover_idx = 3;
        pks[prover_idx] = pk;

        let (prover_key, verifier_key) = ring_setup.keys(&pks).unwrap();
        let prover = ring_setup
            .ring_context()
            .ring_prover(prover_key, prover_idx);
        let item = TestItem::<S>::new(&secret, &prover, rng);

        let commitment = verifier_key.commitment();

        // A verifier with only the encoded params, the commitment and the size.
        let mut buf = Vec::new();
        ring_setup
            .pcs_verifier_params()
            .serialize_compressed(&mut buf)
            .unwrap();
        let pcs_params = PcsVerifierParams::<S>::deserialize_compressed(&buf[..]).unwrap();

        let ring_ctx = RingContext::<S>::new(TEST_RING_SIZE);
        let verifier_key = super::verifier_key_from_commitment::<S>(commitment, pcs_params);
        let verifier = ring_ctx.ring_verifier(verifier_key);
        assert!(item.proof.verify(item.io, &item.ad, &verifier).is_ok());
    }

    #[allow(unused)]
    pub fn verifier_key_builder<S: RingSuite>() {
        use crate::testing::{random_val, random_vec};

        let rng = &mut ark_std::test_rng();
        let ring_setup = RingSetup::<S>::from_rand_insecure(TEST_RING_SIZE, rng);

        let secret = SecretKey::<S>::from_seed(TEST_SEED);
        let pk = secret.public_key();
        let input = Input::from_affine_unchecked(common::random_val(Some(rng)));
        let io = secret.io_pair(input);

        let ring_ctx = ring_setup.ring_context();
        let ring_size = ring_ctx.max_ring_size();
        let prover_idx = random_val::<usize>(Some(rng)) % ring_size;
        let mut pks = random_ring::<S>(ring_size, rng);
        pks[prover_idx] = pk;

        let prover_key = ring_setup.prover_key(&pks).unwrap();
        let prover = ring_ctx.ring_prover(prover_key, prover_idx);
        let proof = secret.prove_ring(io, b"foo", &prover);

        let (mut vk_builder, lookup) = ring_setup.verifier_key_builder();
        assert_eq!(vk_builder.free_slots(), pks.len());

        // An endless iterator must end with an error and add nothing.
        let endless = core::iter::repeat(PublicKey::<S>::padding());
        assert_eq!(
            vk_builder.append(endless, &lookup).unwrap_err(),
            Error::RingCapacityExceeded
        );
        assert_eq!(vk_builder.free_slots(), pks.len());
        assert_eq!(
            vk_builder.pcs_verifier_params(),
            ring_setup.pcs_verifier_params()
        );

        let extra_pk = PublicKey::<S>::from_affine_unchecked(random_val(Some(rng)));
        assert_eq!(
            vk_builder.append([extra_pk], |_| None).unwrap_err(),
            Error::SrsLookupFailed
        );

        while !pks.is_empty() {
            let chunk_len = 1 + random_val::<usize>(Some(rng)) % 5;
            let chunk = pks.drain(..pks.len().min(chunk_len)).collect::<Vec<_>>();
            vk_builder.append(&chunk[..], &lookup).unwrap();
            assert_eq!(vk_builder.free_slots(), pks.len());
        }
        let extra_pk = PublicKey::<S>::from_affine_unchecked(random_val(Some(rng)));
        assert_eq!(
            vk_builder.append([extra_pk], &lookup).unwrap_err(),
            Error::RingCapacityExceeded
        );
        assert_eq!(vk_builder.free_slots(), 0);
        let verifier_key = vk_builder.finalize();
        let verifier = ring_ctx.ring_verifier(verifier_key);
        let res = proof.verify(io, b"foo", &verifier);
        assert!(res.is_ok());
    }

    /// Downstream types that derive `Debug` need `Proof<S>: Debug`. The impl is
    /// manual, so only this test notices if it goes away.
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

            assert!(piop_dom_size >= ring_size + overhead);
            assert!(piop_dom_size / 2 < ring_size + overhead);
            assert_eq!(piop_dom_size, piop_domain_size::<S>(max_ring_size));
            assert!(ring_size <= max_ring_size);

            assert_eq!(dom_utils::max_ring_size::<S>(ring_size), max_ring_size);
            assert_eq!(dom_utils::max_ring_size::<S>(max_ring_size), max_ring_size);

            let piop_dom_rt = piop_domain_size_from_pcs_domain_size(pcs_dom_size).unwrap();
            assert_eq!(piop_dom_size, piop_dom_rt);
            let pcs_dom_rt = pcs_domain_size_from_piop_domain_size(piop_dom_rt);
            assert_eq!(pcs_dom_size, pcs_dom_rt);

            let max_ring_from_pcs = max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size).unwrap();
            assert_eq!(max_ring_size, max_ring_from_pcs);

            let next_piop = piop_domain_size::<S>(max_ring_size + 1);
            assert!(next_piop > piop_dom_size,);
            assert!(next_piop.is_power_of_two());
        }

        // Any PCS size gives the largest PIOP domain that fits in it.
        for pcs_dom_size in [1 << 11, 1 << 12, 1 << 14, 1 << 16] {
            let piop_dom = piop_domain_size_from_pcs_domain_size(pcs_dom_size).unwrap();
            let max_ring = max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size).unwrap();

            assert!(piop_dom.is_power_of_two());
            assert!(3 * piop_dom < pcs_dom_size);
            assert!(3 * (2 * piop_dom) + 1 > pcs_dom_size);
            assert_eq!(piop_domain_size::<S>(max_ring), piop_dom);
            assert!(piop_domain_size::<S>(max_ring + 1) > piop_dom);
        }

        // At or below the overhead no key fits.
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

        // A ring size of 0 counts as 1.
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
                fn prefetched_lookup_serves_the_range_once() {
                    $crate::ring::testing::prefetched_lookup_serves_the_range_once::<$suite>()
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
                #[should_panic(expected = "domain size overflows usize")]
                fn huge_ring_size_panics() {
                    $crate::ring::testing::huge_ring_size_panics::<$suite>()
                }

                #[test]
                fn off_curve_pairing_point_rejected() {
                    $crate::ring::testing::off_curve_pairing_point_rejected::<$suite>()
                }

                #[test]
                fn builder_decode_rejects_foreign_ring_shape() {
                    $crate::ring::testing::builder_decode_rejects_foreign_ring_shape::<$suite>()
                }

                #[test]
                fn identity_in_ring_rejected() {
                    $crate::ring::testing::identity_in_ring_rejected::<$suite>()
                }

                #[test]
                fn exceptional_key_commitment_rejected() {
                    $crate::ring::testing::exceptional_key_commitment_rejected::<$suite>()
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
            // The whole SRS: the ring vectors use the domain of spec section 5.
            RingSetup::deserialize_uncompressed_unchecked(&buf[..]).unwrap()
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
        pub ring_pks: [PublicKey<S>; TEST_RING_SIZE],
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
            let pedersen = pedersen::testing::TestVector::new(comment, seed, alpha, ad);

            let secret = SecretKey::<S>::from_scalar(pedersen.base.sk);
            let pk = secret.public_key();

            let io = IoPair {
                input: Input::<S>::from_affine_unchecked(pedersen.base.h),
                output: Output::from_affine_unchecked(pedersen.base.gamma),
            };

            let ring_setup = <S as RingSuiteExt>::ring_setup();
            let max_ring_size = ring_setup.ring_context().max_ring_size();
            assert_eq!(
                piop_domain_size::<S>(max_ring_size),
                TEST_VECTOR_DOMAIN_SIZE
            );

            use ark_std::rand::SeedableRng;
            let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42; 32]);
            let prover_idx = 3;
            let mut ring_pks = random_ring::<S>(TEST_RING_SIZE, rng);
            ring_pks[prover_idx] = pk;

            // No blinding, so the proof is reproducible.
            let ring_ctx = RingContext::<S>::new_without_blinding(max_ring_size);
            let (prover_key, verifier_key) = ring_setup.keys(&ring_pks).unwrap();
            let prover = ring_ctx.into_ring_prover(prover_key, prover_idx);
            let proof = secret.prove_ring(io, ad, &prover);

            let ring_pks_com = verifier_key.commitment();

            {
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

            let ring_pks = map.get::<[PublicKey<S>; TEST_RING_SIZE]>("ring_pks");
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

            let io = IoPair {
                input: Input::<S>::from_affine_unchecked(self.pedersen.base.h),
                output: Output::from_affine_unchecked(self.pedersen.base.gamma),
            };
            let secret = SecretKey::from_scalar(self.pedersen.base.sk);
            let pk = secret.public_key();
            assert_eq!(pk.0, self.pedersen.base.pk);

            let ring_setup = <S as RingSuiteExt>::ring_setup();

            let prover_idx = self.ring_pks.iter().position(|key| *key == pk).unwrap();

            // No blinding, so the proof is reproducible.
            let ring_ctx =
                RingContext::<S>::new_without_blinding(ring_setup.ring_context().max_ring_size());
            let (prover_key, verifier_key) = ring_setup.keys(self.ring_pks).unwrap();
            let prover = ring_ctx.ring_prover(prover_key, prover_idx);

            assert_eq!(verifier_key.commitment(), self.ring_pks_com);
            let verifier = ring_ctx.ring_verifier(verifier_key);

            let proof = secret.prove_ring(io, &self.pedersen.base.ad, &prover);

            {
                let mut p = (Vec::new(), Vec::new());
                self.pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            {
                let mut p = (Vec::new(), Vec::new());
                self.ring_proof.serialize_compressed(&mut p.0).unwrap();
                proof.ring_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            assert!(proof.verify(io, &self.pedersen.base.ad, &verifier).is_ok());
        }
    }
}
