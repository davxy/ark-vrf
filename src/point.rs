//! Curve points with a role: public key, VRF input and VRF output.

use crate::utils::canonical::CanonicalDeserializeStrict;
use crate::{AffinePoint, Error, Suite};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::marker::PhantomData;

/// Curve point with a role `K`: [`PublicKey`], [`Input`] or [`Output`].
///
/// # Validation
///
/// [`PublicKey`] and [`Output`] come from [`PointWrapper::from_affine`] or from
/// deserialization. [`Input`] comes only from [`Input::new`].
///
/// `from_affine` and the checked decoders (`deserialize_*`) accept only points
/// in the prime-order subgroup, and reject the identity. The verifiers depend
/// on this: they reject the identity, but they do not check subgroup membership
/// again. The unchecked decoders (`deserialize_*_unchecked`) do no validation,
/// so the caller must do it. The same rules apply to the points in the proofs.
///
/// Each value has one accepted encoding. The decoders do not reject trailing
/// bytes; [`CanonicalDeserializeExact`](crate::CanonicalDeserializeExact) does.
#[derive(Debug, Clone, Copy)]
pub struct PointWrapper<S: Suite, K>(pub(crate) AffinePoint<S>, PhantomData<K>);

// Not derived: the derive would require `S: PartialEq` of the suite marker.
impl<S: Suite, K> PartialEq for PointWrapper<S, K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: Suite, K> Eq for PointWrapper<S, K> {}

/// Role marker of [`PublicKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyKind;

/// Role marker of [`Input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputKind;

/// Role marker of [`Output`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputKind;

mod sealed {
    pub trait Sealed {}
}

/// Role markers of the points that serialize. [`InputKind`] is left out, see
/// [`Input`]. The trait is sealed: other crates cannot implement it.
pub trait Serializable: sealed::Sealed + Sync {}

impl sealed::Sealed for PublicKeyKind {}

impl Serializable for PublicKeyKind {}

impl sealed::Sealed for OutputKind {}

impl Serializable for OutputKind {}

/// Public key.
pub type PublicKey<S> = PointWrapper<S, PublicKeyKind>;

/// VRF input point.
///
/// Build it with [`Input::new`] from the input data, on both sides. `Input` has
/// no `from_affine` and no decoder, so a verifier cannot take a point that the
/// prover chose (see the crate "Security" section).
pub type Input<S> = PointWrapper<S, InputKind>;

/// VRF output point.
pub type Output<S> = PointWrapper<S, OutputKind>;

impl<S: Suite, K: Sync> ark_serialize::Valid for PointWrapper<S, K> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        if self.is_identity() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        self.0.check()
    }
}

impl<S: Suite, K: Serializable> CanonicalSerialize for PointWrapper<S, K> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl<S: Suite, K: Serializable> CanonicalDeserialize for PointWrapper<S, K> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let point = AffinePoint::<S>::deserialize_strict(reader, compress, validate)?;
        let wrapper = Self::from_affine_unchecked(point);
        // `check()` ran on the point; the identity rule remains.
        if matches!(validate, ark_serialize::Validate::Yes) && wrapper.is_identity() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(wrapper)
    }
}

impl<S: Suite, K: Sync> PointWrapper<S, K> {
    /// Wrap a point with no validation. The caller makes sure that it is valid.
    pub(crate) fn from_affine_unchecked(value: AffinePoint<S>) -> Self {
        Self(value, PhantomData)
    }

    /// Get the affine point.
    pub fn into_affine(self) -> AffinePoint<S> {
        self.0
    }

    /// Whether the point is the group identity. The verifiers reject it, also
    /// for points that did not go through a checked decoder.
    pub(crate) fn is_identity(&self) -> bool {
        self.0.is_zero()
    }
}

impl<S: Suite, K: Serializable> PointWrapper<S, K> {
    /// Wrap a point. Returns `Error::InvalidData` if the point is not in the
    /// prime-order subgroup or is the identity.
    pub fn from_affine(value: AffinePoint<S>) -> Result<Self, Error> {
        let wrapper = Self::from_affine_unchecked(value);
        ark_serialize::Valid::check(&wrapper).map_err(|_| Error::InvalidData)?;
        Ok(wrapper)
    }
}

impl<S: Suite> Input<S> {
    /// Hash `data` to an input point with [`Suite::data_to_point`].
    ///
    /// Returns `Error::InvalidData` if the map finds no point or gives the
    /// identity. Subgroup membership is not checked (see
    /// [`Suite::data_to_point`]).
    pub fn new(data: &[u8]) -> Result<Self, Error> {
        S::data_to_point(data)
            .map(Self::from_affine_unchecked)
            .filter(|input| !input.is_identity())
            .ok_or(Error::InvalidData)
    }
}

impl<S: Suite> Output<S> {
    /// Hash the output point to `N` bytes.
    pub fn hash<const N: usize>(&self) -> [u8; N] {
        S::point_to_hash(&self.0)
    }
}

/// VRF input-output pair.
///
/// The pair does not implement the serialization traits, because [`Input`]
/// does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoPair<S: Suite> {
    /// Input point, from [`Input::new`].
    pub input: Input<S>,
    /// Output point: the input times the secret scalar.
    pub output: Output<S>,
}

impl<S: Suite> AsRef<[IoPair<S>]> for IoPair<S> {
    fn as_ref(&self) -> &[IoPair<S>] {
        core::slice::from_ref(self)
    }
}

impl<S: Suite> IoPair<S> {
    /// Whether a point of the pair is the identity. The verifiers reject such a
    /// pair.
    pub(crate) fn has_identity(&self) -> bool {
        self.input.is_identity() || self.output.is_identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suites::testing::{Input, SecretKey, TestSuite};
    use crate::testing::TEST_SEED;
    use crate::{BaseField, ScalarField, utils};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_std::vec::Vec;

    /// `Input::new` must work with `?`, and a map that finds no point must give
    /// `Error::InvalidData`.
    #[test]
    fn input_new_returns_crate_error() {
        #[derive(Debug, Copy, Clone)]
        struct NeverSuite;

        impl Suite for NeverSuite {
            const SUITE_ID: &'static [u8] = b"Never";
            type Affine = <TestSuite as Suite>::Affine;
            type Transcript = <TestSuite as Suite>::Transcript;

            fn data_to_point(_data: &[u8]) -> Option<AffinePoint<Self>> {
                None
            }
        }

        fn build() -> Result<Input, Error> {
            let input = Input::new(b"data")?;
            Ok(input)
        }
        assert!(build().is_ok());
        assert_eq!(
            crate::Input::<NeverSuite>::new(b"data").unwrap_err(),
            Error::InvalidData
        );
    }

    /// The wrapper has no `Deref`, so the roles stay distinct. `into_affine` is
    /// the only way to read the point.
    #[test]
    fn point_wrapper_point_accessor() {
        let public = SecretKey::from_seed(TEST_SEED).public();
        assert_eq!(public.into_affine(), public.0);
    }

    /// The subgroup check accepts the identity. Its secret key is zero, so the
    /// checked decoder must reject it on its own.
    #[test]
    fn identity_public_key_construction_rejected() {
        type S = TestSuite;

        let identity = AffinePoint::<S>::zero();
        assert!(ark_serialize::Valid::check(&identity).is_ok());

        let mut buf = Vec::new();
        identity.serialize_compressed(&mut buf).unwrap();
        assert!(crate::PublicKey::<S>::deserialize_compressed(&buf[..]).is_err());

        // Unchecked paths are documented as skipping validation.
        assert!(crate::PublicKey::<S>::deserialize_compressed_unchecked(&buf[..]).is_ok());
        assert!(crate::PublicKey::<S>::from_affine_unchecked(identity).is_identity());
    }

    /// The pair `(0, 0)` satisfies `O = x * I` for every key and passes the
    /// subgroup check, so the checked decoder must reject it on its own.
    #[test]
    fn identity_io_point_construction_rejected() {
        type S = TestSuite;

        let identity = AffinePoint::<S>::zero();

        let mut buf = Vec::new();
        identity.serialize_compressed(&mut buf).unwrap();
        assert!(crate::Output::<S>::deserialize_compressed(&buf[..]).is_err());

        // Unchecked paths are documented as skipping validation.
        assert!(crate::Output::<S>::deserialize_compressed_unchecked(&buf[..]).is_ok());
        assert!(crate::Input::<S>::from_affine_unchecked(identity).is_identity());
        assert!(crate::Output::<S>::from_affine_unchecked(identity).is_identity());
    }

    /// An unchecked output `O + L`, with `L` of order 2, verifies for some `ad`
    /// and hashes to another VRF output. Only the subgroup check of the
    /// decoders stops it.
    #[test]
    fn prove_uniqueness_vulnerability() {
        use ark_ff::BigInteger;
        use ark_std::{One, Zero};
        use utils::common::DomSep;

        type S = TestSuite;
        type Sc = ScalarField<S>;

        let secret = crate::SecretKey::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::new(b"uniqueness attack").unwrap();
        let honest_output = secret.output(input);

        // (0, -1) has order 2 on Ed25519.
        let low_order_pt =
            AffinePoint::<S>::new_unchecked(BaseField::<S>::zero(), -BaseField::<S>::one());
        assert!(!low_order_pt.is_zero());
        assert!((low_order_pt.into_group() + low_order_pt.into_group()).is_zero());

        let malicious_output =
            Output::from_affine_unchecked((honest_output.0 + low_order_pt).into_affine());
        assert_ne!(honest_output, malicious_output);
        assert_ne!(honest_output.hash::<32>(), malicious_output.hash::<32>());

        // The forgery verifies when `c * z_1 * L = 0`. Find an `ad` that gives
        // an even `z_1`, then grind `k` for an odd `c`.
        let malicious_io = IoPair {
            input,
            output: malicious_output,
        };
        let mal_ios = [malicious_io];

        let mut ad_ctr = 0u32;
        let (ad, t, merged_input) = loop {
            let ad = format!("ad-{ad_ctr}");
            let (t, zs) = utils::vrf_transcript_scalars_with_schnorr(
                DomSep::TinyVrf,
                public.0,
                mal_ios,
                ad.as_bytes(),
            );
            if zs[1].into_bigint().is_even() {
                let i_m = (S::GENERATOR * zs[0] + input.0 * zs[1]).into_affine();
                break (ad, t, i_m);
            }
            ad_ctr += 1;
            assert!(ad_ctr < 100, "Failed to find suitable ad");
        };

        // An odd `c` makes `q - c` even, so `(-c) * L = 0`.
        let mut ctr = 0u64;
        let proof = loop {
            let mut k_seed = [0u8; 8];
            k_seed.copy_from_slice(&ctr.to_le_bytes());
            let k = Sc::from_le_bytes_mod_order(&k_seed);
            let r = (merged_input * k).into_affine();

            let c = S::challenge(&[&r], t.clone());

            if !c.into_bigint().is_even() {
                let s = k + c * secret.scalar().expose_secret();
                break crate::tiny::Proof { c, s };
            }
            ctr += 1;
            assert!(ctr <= 1000, "Grinding failed");
        };

        assert!(
            public
                .verify_tiny(malicious_io, ad.as_bytes(), &proof)
                .is_ok()
        );

        let honest_io = IoPair {
            input,
            output: honest_output,
        };
        let honest_proof = secret.prove_tiny(honest_io, ad.as_bytes());
        assert!(
            public
                .verify_tiny(honest_io, ad.as_bytes(), &honest_proof)
                .is_ok()
        );

        // Two different outputs for the same input and public key.
        assert_ne!(honest_output.hash::<32>(), malicious_output.hash::<32>());
    }
}
