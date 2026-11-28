//! # Tiny VRF
//!
//! VRF-AD with a short `(c, s)` proof. The proof holds the challenge instead
//! of the nonce commitment, so it is smaller than a Thin VRF proof but cannot
//! be batch verified.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::tiny::Proof;
//!
//! let secret = SecretKey::from_seed([0; 32]);
//! let pk = secret.public_key();
//! let input = Input::new(b"example input").unwrap();
//! let io = secret.io_pair(input);
//!
//! // Proving
//! let proof = Proof::prove(io, b"aux data", &secret);
//!
//! // Verification
//! let res = proof.verify(io, b"aux data", &pk);
//!
//! // The same, as methods of the keys
//! let proof = secret.prove_tiny(io, b"aux data");
//! let res = pk.verify_tiny(io, b"aux data", &proof);
//! ```

use super::*;
use utils::common::{DomSep, ProjectiveZ, stack_buf};

/// Suites with Tiny VRF. Every [`Suite`] implements it.
pub trait TinySuite: Suite {}

impl<T> TinySuite for T where T: Suite {}

#[inline(always)]
fn vrf_transcript_input<S: TinySuite>(
    pk: PublicKey<S>,
    ios: impl AsRef<[IoPair<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Input<S>) {
    utils::vrf_transcript_input_with_schnorr(DomSep::TinyVrf, pk, ios, ad)
}

#[inline(always)]
fn vrf_transcript_scalars<S: TinySuite>(
    pk: PublicKey<S>,
    ios: impl AsRef<[IoPair<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, Vec<ScalarField<S>>) {
    utils::vrf_transcript_scalars_with_schnorr(DomSep::TinyVrf, pk, ios, ad)
}

/// Tiny VRF proof: the challenge `c` and the response `s = k + c * x`.
///
/// The encoding holds `c` on [`Suite::CHALLENGE_LEN`] bytes and `s` as a full
/// scalar. Decoding follows the rules in [`PointWrapper`].
#[derive(Debug, Clone)]
pub struct Proof<S: TinySuite> {
    pub(crate) c: ScalarField<S>,
    pub(crate) s: ScalarField<S>,
}

const fn scalar_len<S: TinySuite>() -> usize {
    ScalarField::<S>::MODULUS_BIT_SIZE.div_ceil(8) as usize
}

/// [`Suite::CHALLENGE_LEN`], checked at compile time against the scalar length.
const fn challenge_len<S: TinySuite>() -> usize {
    assert!(
        S::CHALLENGE_LEN <= scalar_len::<S>(),
        "Suite::CHALLENGE_LEN exceeds the scalar field byte length"
    );
    S::CHALLENGE_LEN
}

impl<S: TinySuite> CanonicalSerialize for Proof<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        stack_buf!(c_buf, scalar_len::<S>());
        self.c
            .serialize_compressed(&mut c_buf[..])
            .expect("c_buf is big enough");
        writer.write_all(&c_buf[..const { challenge_len::<S>() }])?;
        self.s.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let challenge_len = const { challenge_len::<S>() };
        challenge_len + self.s.serialized_size(compress)
    }
}

impl<S: TinySuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        stack_buf!(c_buf, const { challenge_len::<S>() });
        if reader.read_exact(&mut c_buf[..]).is_err() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let c = ScalarField::<S>::from_le_bytes_mod_order(c_buf);
        stack_buf!(canonical, scalar_len::<S>());
        c.serialize_compressed(&mut canonical[..])
            .expect("canonical is big enough");
        if canonical[..c_buf.len()] != c_buf[..] {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        Ok(Proof { c, s })
    }
}

impl<S: TinySuite> ark_serialize::Valid for Proof<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.c.check()?;
        self.s.check()?;
        Ok(())
    }
}

impl<S: TinySuite> Proof<S> {
    /// Prove the VRF I/O pairs `ios` with the additional data `ad`.
    pub fn prove(
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        secret: &SecretKey<S>,
    ) -> Self {
        let (t, input) = vrf_transcript_input::<S>(secret.public_key(), ios, ad);

        let k = S::nonce(secret.scalar(), secret.nonce_transcript(&t));
        let r = k.mul_point(input.0).into_affine();

        let c = S::challenge(&[&r], t);
        let s = k.response(c, secret.scalar());
        Proof { c, s }
    }

    /// Verify the proof for the VRF I/O pairs `ios`, the additional data `ad`
    /// and the key `pk`.
    ///
    /// Returns `Error::InvalidData` if the key or a point of `ios` is the
    /// identity, and `Error::VerificationFailure` if the proof is not valid.
    /// Subgroup membership is not checked (see [`PointWrapper`]).
    pub fn verify(
        &self,
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        pk: &PublicKey<S>,
    ) -> Result<(), Error> {
        let ios = ios.as_ref();
        if utils::has_identity(pk.0, ios) {
            return Err(Error::InvalidData);
        }

        let (t, zs) = vrf_transcript_scalars::<S>(*pk, ios, ad);

        let Proof { c, s } = self;

        // R = s * I_m - c * O_m
        let r = utils::schnorr_lhs::<S>(*pk, ios, &zs, *s, *c)
            .into_affine_checked()
            .ok_or(Error::VerificationFailure)?;

        let c_exp = S::challenge(&[&r], t);
        (c_exp == *c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

impl<S: TinySuite> SecretKey<S> {
    /// Generate a Tiny VRF proof. Same as [`Proof::prove`].
    pub fn prove_tiny(&self, ios: impl AsRef<[IoPair<S>]>, ad: impl AsRef<[u8]>) -> Proof<S> {
        Proof::prove(ios, ad, self)
    }
}

impl<S: TinySuite> PublicKey<S> {
    /// Verify a Tiny VRF proof. Same as [`Proof::verify`].
    pub fn verify_tiny(
        &self,
        ios: impl AsRef<[IoPair<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        proof.verify(ios, ad, self)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::testing::{self as common, SuiteExt};

    pub fn prove_verify<S: TinySuite>() {
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();
        let input = Input::from_affine_unchecked(common::random_val(None));
        let io = secret.io_pair(input);

        let proof = secret.prove_tiny(io, b"foo");
        let res = pk.verify_tiny(io, b"foo", &proof);
        assert!(res.is_ok());
    }

    pub fn prove_verify_multi_empty<S: TinySuite>() {
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();

        let ios: [IoPair<S>; 0] = [];
        let proof = secret.prove_tiny(ios, b"bar");

        assert!(pk.verify_tiny(ios, b"bar", &proof).is_ok());
        assert!(pk.verify_tiny(ios, b"baz", &proof).is_err());
    }

    /// N=1 slice produces same proof as passing a single `IoPair`.
    pub fn prove_verify_multi_single<S: TinySuite>() {
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();
        let input = Input::from_affine_unchecked(common::random_val(None));
        let io = secret.io_pair(input);

        let proof_single = secret.prove_tiny(io, b"foo");
        let proof_slice = secret.prove_tiny([io], b"foo");

        let encode = |p: &tiny::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));
        assert!(pk.verify_tiny(io, b"foo", &proof_slice).is_ok());
        assert!(pk.verify_tiny([io], b"foo", &proof_single).is_ok());
    }

    /// The secret key of `Y = 0` is zero, so anybody can build this proof. The
    /// verifier must reject it also for a key that skipped the checked decoder.
    pub fn identity_public_key_rejected<S: TinySuite>() {
        let identity = PublicKey::<S>::from_affine_unchecked(AffinePoint::<S>::zero());
        let zero_secret = SecretKey::<S>::from_scalar(ScalarField::<S>::zero());

        let proof = zero_secret.prove_tiny([], b"forgery");
        assert!(identity.verify_tiny([], b"forgery", &proof).is_err());
    }

    /// `(0, 0)` satisfies `O = x * I` for every key, so it binds its output to no
    /// signer. The second case hides it behind a valid pair, where the merged
    /// pair does not show it.
    pub fn identity_io_pair_rejected<S: TinySuite>() {
        let identity_io = IoPair::<S> {
            input: Input::from_affine_unchecked(AffinePoint::<S>::zero()),
            output: Output::from_affine_unchecked(AffinePoint::<S>::zero()),
        };

        for seed in [common::TEST_SEED, [0x11; 32]] {
            let secret = SecretKey::<S>::from_seed(seed);
            let pk = secret.public_key();

            let proof = secret.prove_tiny([identity_io], b"forgery");
            assert!(pk.verify_tiny([identity_io], b"forgery", &proof).is_err());

            let good_io = secret.io_pair(Input::new(b"good").unwrap());
            let ios = [good_io, identity_io];
            let proof = secret.prove_tiny(ios, b"forgery");
            assert!(pk.verify_tiny(ios, b"forgery", &proof).is_err());
        }
    }

    /// An off-curve key or input, such as `(0, 0)` on a twisted Edwards curve,
    /// gives `R = (0, 0, 0, 0)`, which has no affine form. Verify must return an
    /// error and not panic.
    pub fn off_curve_point_rejected<S: TinySuite>() {
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let io = secret.io_pair(Input::new(b"foo").unwrap());
        let proof = secret.prove_tiny(io, b"bar");
        let off_curve = common::off_curve_point::<S>();

        let pk = PublicKey::<S>::from_affine_unchecked(off_curve);
        assert!(pk.verify_tiny(io, b"bar", &proof).is_err());

        let input = Input::from_affine_unchecked(off_curve);
        let io = IoPair { input, ..io };
        assert!(secret.public_key().verify_tiny(io, b"bar", &proof).is_err());
    }

    /// N=3 multi proof: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: TinySuite>() {
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();

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

        let proof = secret.prove_tiny(&ios[..], b"bar");
        assert!(pk.verify_tiny(&ios[..], b"bar", &proof).is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(pk.verify_tiny(&bad_ios[..], b"bar", &proof).is_err());

        let mut bad_ios = ios.clone();
        bad_ios[0].input = ios[1].input;
        assert!(pk.verify_tiny(&bad_ios[..], b"bar", &proof).is_err());

        assert!(pk.verify_tiny(&ios[..], b"baz", &proof).is_err());
    }

    /// Runs the MSM branch of `merge_ios` (`MSM_THRESHOLD` pairs) through prove
    /// and verify.
    pub fn prove_verify_multi_msm<S: TinySuite>() {
        use crate::utils::common::MSM_THRESHOLD;

        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();
        let ios: Vec<IoPair<S>> = (0..MSM_THRESHOLD as u8)
            .map(|i| secret.io_pair(Input::new(&[i]).unwrap()))
            .collect();

        let proof = secret.prove_tiny(&ios[..], b"msm");
        assert!(pk.verify_tiny(&ios[..], b"msm", &proof).is_ok());

        let mut bad_ios = ios.clone();
        bad_ios[MSM_THRESHOLD - 1].output = ios[0].output;
        assert!(pk.verify_tiny(&bad_ios[..], b"msm", &proof).is_err());
    }

    /// A hedged key must use a new nonce in each proof on the same data. With
    /// the same nonce, a fault in one challenge discloses the secret key.
    #[cfg(feature = "hedged-nonce")]
    #[test]
    fn hedged_key_uses_new_nonces() {
        use crate::suites::testing::TestSuite as S;

        let secret = SecretKey::<S>::from_seed(common::TEST_SEED).with_hedged_nonce();
        let pk = secret.public_key();
        let io = secret.io_pair(Input::new(b"input").unwrap());
        let first = secret.prove_tiny(io, b"ad");
        let second = secret.prove_tiny(io, b"ad");
        assert!(pk.verify_tiny(io, b"ad", &first).is_ok());
        assert!(pk.verify_tiny(io, b"ad", &second).is_ok());
        assert_ne!(first.s, second.s);
    }

    #[macro_export]
    macro_rules! tiny_suite_tests {
        ($suite:ty) => {
            mod tiny {
                use super::*;

                #[test]
                fn prove_verify() {
                    $crate::tiny::testing::prove_verify::<$suite>();
                }

                #[test]
                fn prove_verify_multi_single() {
                    $crate::tiny::testing::prove_verify_multi_single::<$suite>();
                }

                #[test]
                fn prove_verify_multi() {
                    $crate::tiny::testing::prove_verify_multi::<$suite>();
                }

                #[test]
                fn prove_verify_multi_empty() {
                    $crate::tiny::testing::prove_verify_multi_empty::<$suite>();
                }

                #[test]
                fn prove_verify_multi_msm() {
                    $crate::tiny::testing::prove_verify_multi_msm::<$suite>();
                }

                #[test]
                fn identity_public_key_rejected() {
                    $crate::tiny::testing::identity_public_key_rejected::<$suite>();
                }

                #[test]
                fn identity_io_pair_rejected() {
                    $crate::tiny::testing::identity_io_pair_rejected::<$suite>();
                }

                #[test]
                fn off_curve_point_rejected() {
                    $crate::tiny::testing::off_curve_point_rejected::<$suite>();
                }

                $crate::test_vectors!($crate::tiny::testing::TestVector<$suite>);
            }
        };
    }

    pub struct TestVector<S: TinySuite> {
        pub base: common::TestVector<S>,
        pub c: ScalarField<S>,
        pub s: ScalarField<S>,
    }

    impl<S: TinySuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let c = hex::encode(common::scalar_encode::<S>(&self.c));
            let s = hex::encode(common::scalar_encode::<S>(&self.s));
            f.debug_struct("TestVector")
                .field("base", &self.base)
                .field("proof_c", &c)
                .field("proof_s", &s)
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: TinySuite + SuiteExt + std::fmt::Debug,
    {
        fn name() -> String {
            S::SUITE_NAME.to_string() + "_tiny"
        }

        fn new(comment: &str, seed: &[u8; 32], alpha: &[u8], ad: &[u8]) -> Self {
            let base = common::TestVector::new(comment, seed, alpha, ad);
            let io = IoPair {
                input: Input::from_affine_unchecked(base.h),
                output: Output::from_affine_unchecked(base.gamma),
            };
            let sk = SecretKey::from_scalar(base.sk);
            let proof: Proof<S> = sk.prove_tiny(io, ad);
            Self {
                base,
                c: proof.c,
                s: proof.s,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let c = common::scalar_decode::<S>(&map.get_bytes("proof_c"));
            let s = common::scalar_decode::<S>(&map.get_bytes("proof_s"));
            Self { base, c, s }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let buf = common::scalar_encode::<S>(&self.c);
            let proof_c = &buf[..S::CHALLENGE_LEN];
            let items = [
                ("proof_c", hex::encode(proof_c)),
                ("proof_s", hex::encode(common::scalar_encode::<S>(&self.s))),
            ];
            let mut map = self.base.to_map();
            items.into_iter().for_each(|(name, value)| {
                map.0.insert(name.to_string(), value);
            });
            map
        }

        fn run(&self) {
            self.base.run();
            let io = IoPair {
                input: Input::<S>::from_affine_unchecked(self.base.h),
                output: Output::from_affine_unchecked(self.base.gamma),
            };
            let sk = SecretKey::from_scalar(self.base.sk);
            let proof = sk.prove_tiny(io, &self.base.ad);
            assert_eq!(self.c, proof.c, "VRF proof challenge ('c') mismatch");
            assert_eq!(self.s, proof.s, "VRF proof response ('s') mismatch");

            let pk = PublicKey::<S>::from_affine_unchecked(self.base.pk);
            assert!(pk.verify_tiny(io, &self.base.ad, &proof).is_ok());
        }
    }

    /// `Suite::SECURITY_PARAMETER` sizes the challenge and the Tiny encoding
    /// of it: a suite at 256 bits writes `c` on 32 bytes and reads it back.
    #[test]
    fn challenge_encoding_follows_security_parameter() {
        use crate::suites::testing::TestSuite256 as S;

        assert_eq!(S::CHALLENGE_LEN, 32);
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();
        let io = secret.io_pair(Input::new(b"wide").unwrap());
        let proof = secret.prove_tiny(io, b"ad");
        let c_bytes = common::scalar_encode::<S>(&proof.c);
        assert!(c_bytes[16..].iter().any(|byte| *byte != 0));

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes.len(), proof.compressed_size());
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(pk.verify_tiny(io, b"ad", &decoded).is_ok());
    }

    /// At the full scalar width, `c + q` also reduces to `c`, so the decoder must
    /// reject it to keep one encoding per proof.
    #[test]
    fn challenge_len_can_exceed_the_level() {
        use crate::suites::testing::TestSuiteC32 as S;
        use ark_ff::BigInteger;

        assert_eq!(S::SECURITY_PARAMETER, 128);
        assert_eq!(S::CHALLENGE_LEN, 32);
        let secret = SecretKey::<S>::from_seed(common::TEST_SEED);
        let pk = secret.public_key();
        let io = secret.io_pair(Input::new(b"wide").unwrap());
        let proof = secret.prove_tiny(io, b"ad");
        let c_bytes = common::scalar_encode::<S>(&proof.c);
        assert!(c_bytes[16..].iter().any(|byte| *byte != 0));

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64);
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(pk.verify_tiny(io, b"ad", &decoded).is_ok());

        let mut alias = proof.c.into_bigint();
        assert!(!alias.add_with_carry(&ScalarField::<S>::MODULUS));
        bytes[..32].copy_from_slice(&alias.to_bytes_le());
        assert!(Proof::<S>::deserialize_compressed(&bytes[..]).is_err());
        assert!(Proof::<S>::deserialize_compressed_unchecked(&bytes[..]).is_err());
    }
}
