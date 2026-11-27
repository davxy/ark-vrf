//! Secret key and secret scalars.

use crate::utils::{self, transcript::Transcript};
use crate::{AffinePoint, Input, IoPair, Output, PublicKey, ScalarField, Suite};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret scalar: a secret key, a nonce or a blinding factor.
///
/// It is zeroized on drop and redacted in `Debug`. Temporaries inside arkworks
/// and the ring proof backend are not zeroized. [`Self::expose`] gives the value,
/// for example to reveal a blinding factor.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar<S: Suite>(ScalarField<S>);

impl<S: Suite> SecretScalar<S> {
    /// Wrap a secret scalar.
    pub fn new(scalar: ScalarField<S>) -> Self {
        Self(scalar)
    }

    /// The scalar value.
    pub fn expose(&self) -> &ScalarField<S> {
        &self.0
    }

    /// `self * point`. With `secret-split`, the multiplier is `self + r * n`,
    /// with a fresh random 128-bit `r` and the group order `n`, so `point` must
    /// be in the prime-order subgroup. It runs in variable time.
    pub fn mul_point(&self, point: AffinePoint<S>) -> <AffinePoint<S> as AffineRepr>::Group {
        #[cfg(feature = "secret-split")]
        {
            use rand::Rng;
            let mut blinded = blind::<S>(&self.0, rand::rngs::OsRng.r#gen());
            let product = point.mul_bigint(&blinded);
            blinded.as_mut_slice().zeroize();
            product
        }
        #[cfg(not(feature = "secret-split"))]
        {
            point * self.0
        }
    }

    /// The response `self + c * x`, which is public.
    pub(crate) fn response(&self, c: ScalarField<S>, x: &Self) -> ScalarField<S> {
        let mut cx = c * x.0;
        let s = self.0 + cx;
        cx.zeroize();
        s
    }
}

/// `k + r * n` as little-endian limbs, with `n` the scalar field modulus.
#[cfg(feature = "secret-split")]
fn blind<S: Suite>(k: &ScalarField<S>, r: u128) -> ark_std::vec::Vec<u64> {
    let modulus = ScalarField::<S>::MODULUS;
    let modulus = modulus.as_ref();
    let mut k_limbs = k.into_bigint();
    let mut blinded = ark_std::vec![0u64; modulus.len() + 2];
    blinded[..modulus.len()].copy_from_slice(k_limbs.as_ref());
    k_limbs.as_mut().zeroize();

    for (shift, r_limb) in [r as u64, (r >> 64) as u64].into_iter().enumerate() {
        let n_limbs = modulus.iter().copied().chain(core::iter::repeat(0));
        let mut carry = 0u128;
        for (limb, n_limb) in blinded[shift..].iter_mut().zip(n_limbs) {
            let sum = u128::from(*limb) + u128::from(n_limb) * u128::from(r_limb) + carry;
            *limb = sum as u64;
            carry = sum >> 64;
        }
    }
    blinded
}

impl<S: Suite> core::fmt::Debug for SecretScalar<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretScalar(<redacted>)")
    }
}

/// Secret key: the secret scalar and its public key.
///
/// The scalar is a [`SecretScalar`], compared in constant time. The caller owns
/// the Pedersen blinding factor (see [`pedersen::Proof::prove`](crate::pedersen::Proof::prove)).
#[derive(Clone)]
pub struct SecretKey<S: Suite> {
    pub(crate) scalar: SecretScalar<S>,
    pub(crate) public: PublicKey<S>,
}

impl<S: Suite> core::fmt::Debug for SecretKey<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretKey")
            .field("scalar", &self.scalar)
            .field("public", &self.public.0)
            .finish()
    }
}

impl<S: Suite> ZeroizeOnDrop for SecretKey<S> {}

impl<S: Suite> PartialEq for SecretKey<S> {
    /// Timing does not depend on the scalars content or on where they differ.
    fn eq(&self, other: &Self) -> bool {
        let mut lhs = self.scalar.0.into_bigint();
        let mut rhs = other.scalar.0.into_bigint();
        let diff = lhs
            .as_ref()
            .iter()
            .zip(rhs.as_ref())
            .fold(0u64, |acc, (a, b)| acc | (a ^ b));
        lhs.as_mut().zeroize();
        rhs.as_mut().zeroize();
        diff == 0
    }
}

impl<S: Suite> CanonicalSerialize for SecretKey<S> {
    fn serialize_with_mode<W: ark_std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.scalar.0.serialized_size(compress)
    }
}

impl<S: Suite> CanonicalDeserialize for SecretKey<S> {
    fn deserialize_with_mode<R: ark_std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let scalar = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            reader, compress, validate,
        )?;
        Ok(Self::from_scalar(scalar))
    }
}

impl<S: Suite> ark_serialize::Valid for SecretKey<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.0.check()
    }
}

impl<S: Suite> SecretKey<S> {
    /// Construct a `SecretKey` from the given scalar.
    pub fn from_scalar(scalar: ScalarField<S>) -> Self {
        Self::from_secret_scalar(SecretScalar::new(scalar))
    }

    fn from_secret_scalar(scalar: SecretScalar<S>) -> Self {
        let public = PublicKey::from_affine_unchecked(scalar.mul_point(S::GENERATOR).into_affine());
        Self { scalar, public }
    }

    /// Derive a `SecretKey` from a seed with the suite transcript.
    ///
    /// The scalar is in `[1, n - 1]`, with no clamping and no cofactor
    /// multiplication.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let mut cnt = 0_u8;
        let sk = SecretScalar::new(ScalarField::<S>::from_le_bytes_mod_order(&seed));
        let scalar = loop {
            let mut transcript = S::Transcript::new(S::SUITE_ID);
            transcript.absorb_raw(&seed);
            if cnt > 0 {
                transcript.absorb_raw(&[cnt]);
            }
            let scalar = utils::nonce::<S>(&sk, transcript);
            if !scalar.0.is_zero() {
                break scalar;
            }
            cnt = cnt
                .checked_add(1)
                .expect("unreachable: transcript hash produced 256 consecutive zero scalars");
        };
        seed.zeroize();
        Self::from_secret_scalar(scalar)
    }

    /// Random `SecretKey` from `rng`.
    pub fn from_rand(rng: &mut impl ark_std::rand::RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let secret = Self::from_seed(seed);
        seed.zeroize();
        secret
    }

    /// Get the secret scalar.
    pub fn scalar(&self) -> &SecretScalar<S> {
        &self.scalar
    }

    /// Get the associated public key.
    pub fn public(&self) -> PublicKey<S> {
        self.public
    }

    /// Get the VRF output point relative to input.
    pub fn output(&self, input: Input<S>) -> Output<S> {
        Output::from_affine_unchecked(self.scalar.mul_point(input.0).into_affine())
    }

    /// Get the VRF input-output pair relative to input.
    pub fn io_pair(&self, input: Input<S>) -> IoPair<S> {
        IoPair {
            input,
            output: self.output(input),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::suites::testing::{Input, SecretKey, SecretScalar, TestSuite};
    use crate::testing::{TEST_SEED, random_val};

    #[test]
    fn vrf_output_check() {
        use ark_std::rand::SeedableRng;
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([42; 32]);
        let secret = SecretKey::from_seed(TEST_SEED);
        let input = Input::from_affine_unchecked(random_val(Some(&mut rng)));
        let output = secret.output(input);

        let expected = "4af9bf572a107a8f61faa380667efe27eaf399cc8e718d57ef328924eb51d450";
        assert_eq!(expected, hex::encode(output.hash::<32>()));
    }

    /// One `{:?}` on a secret in a downstream log must not leak the key.
    #[test]
    fn secret_debug_redacts_scalar() {
        let secret = SecretKey::from_seed(TEST_SEED);
        let out = std::format!("{:?}", secret);
        let scalar_str = std::format!("{:?}", secret.scalar().expose());
        assert!(!out.contains(&scalar_str));
    }

    /// One `{:?}` on a nonce or a blinding factor in a downstream log must not
    /// leak it.
    #[test]
    fn secret_scalar_debug_redacts_scalar() {
        let scalar = ScalarField::<TestSuite>::from(0x5eed_u64);
        let out = std::format!("{:?}", SecretScalar::new(scalar));
        assert!(!out.contains(&std::format!("{scalar:?}")));
    }

    /// Equality semantics must survive the switch to the constant-time impl.
    #[test]
    fn secret_partial_eq() {
        let secret = SecretKey::from_seed(TEST_SEED);
        assert_eq!(secret, SecretKey::from_seed(TEST_SEED));
        assert_ne!(secret, SecretKey::from_seed([0xff; 32]));
    }

    /// The largest `k` and `r` must not overflow the limbs, and the blinded
    /// scalar must multiply a prime-order point like `k`. With secp256r1,
    /// `k + r * n` fills all the limbs.
    #[cfg(feature = "secret-split")]
    pub(crate) fn blind_largest_values<S: Suite>() {
        let k = -ScalarField::<S>::from(1u64);
        let blinded = blind::<S>(&k, u128::MAX);

        let bytes: std::vec::Vec<u8> = blinded.iter().flat_map(|limb| limb.to_le_bytes()).collect();
        assert_eq!(ScalarField::<S>::from_le_bytes_mod_order(&bytes), k);
        let k_len = k.into_bigint().as_ref().len();
        assert!(blinded[k_len..].iter().any(|&limb| limb != 0));
        assert_eq!(S::GENERATOR.mul_bigint(&blinded), S::GENERATOR * k);
    }
}
