//! # Tiny VRF
//!
//! Compact VRF-AD scheme producing a short `(c, s)` proof. Prepends the Schnorr
//! pair `(G, Y)` to the I/O list and proves a single DLEQ on the delinearized
//! merged pair. The challenge scalar `c` is stored instead of the nonce commitment,
//! yielding a smaller proof at the cost of not supporting batch verification.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ark_vrf::suites::bandersnatch::*;
//! use ark_vrf::tiny::{Prover, Verifier};
//!
//! let secret = Secret::from_seed([0; 32]);
//! let public = secret.public();
//! let input = Input::new(b"example input").unwrap();
//! let io = secret.vrf_io(input);
//!
//! // Proving
//! let proof = secret.prove(io, b"aux data");
//!
//! // Verification
//! let result = public.verify(io, b"aux data", &proof);
//! ```

use super::*;
use utils::common::{DomSep, stack_buf};
use utils::straus::short_msm;

/// Marker trait for suites that support the Tiny VRF scheme.
///
/// Blanket-implemented for all types implementing [`Suite`].
pub trait TinySuite: Suite {}

impl<T> TinySuite for T where T: Suite {}

#[inline(always)]
fn vrf_transcript<S: TinySuite>(
    public: AffinePoint<S>,
    ios: impl AsRef<[VrfIo<S>]>,
    ad: impl AsRef<[u8]>,
) -> (S::Transcript, VrfIo<S>) {
    utils::vrf_transcript_with_schnorr(DomSep::TinyVrf, public, ios, ad)
}

/// Tiny VRF proof.
///
/// Schnorr-like proof over the delinearized merged DLEQ relation:
/// - `c`: Challenge scalar
/// - `s`: Response scalar (`s = k + c * x`)
///
/// Construct it with [`Prover::prove`] or by deserialization. Serialization
/// encodes `c` on [`Suite::CHALLENGE_LEN`] bytes and `s` as a full scalar, and
/// accepts one encoding per `c`. The proof holds no curve points, so
/// deserialization involves no subgroup checks.
#[derive(Debug, Clone)]
pub struct Proof<S: TinySuite> {
    /// Challenge scalar.
    pub(crate) c: ScalarField<S>,
    /// Response scalar.
    pub(crate) s: ScalarField<S>,
}

const fn scalar_len<S: TinySuite>() -> usize {
    ScalarField::<S>::MODULUS_BIT_SIZE.div_ceil(8) as usize
}

/// [`Suite::CHALLENGE_LEN`], checked against the scalar field byte length
/// at compile time: the proof encodes `c` on that length.
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

/// Trait for types that can generate Tiny VRF proofs.
pub trait Prover<S: TinySuite> {
    /// Generate a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before proving.
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for types that can verify Tiny VRF proofs.
///
/// Verifies that a VRF output is correctly derived from an input using the
/// secret key of the given public key.
///
/// All curve points involved in verification (public key and I/O pairs)
/// are assumed to be in the prime-order subgroup. This is guaranteed
/// when points are constructed through checked constructors ([`Public::from_affine`],
/// [`Input::from_affine`], [`Output::from_affine`]) or through trusted
/// operations like [`Input::new`] (hash-to-curve) and [`Secret::vrf_io`].
///
/// Using unchecked constructors (e.g. [`Input::from_affine_unchecked`]) places
/// the burden of subgroup validation on the caller. Passing points with
/// cofactor components leads to undefined verification behavior.
///
/// The group identity is checked unconditionally, for the public key and for
/// every I/O pair. Neither binds the proof to a signer: the secret scalar of
/// the identity key is publicly known, and a pair holding the identity is
/// satisfied by every secret key.
pub trait Verifier<S: TinySuite> {
    /// Verify a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before verifying.
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::InvalidData)` if the
    /// public key or any I/O pair point is the group identity,
    /// `Err(Error::VerificationFailure)` otherwise.
    ///
    /// Subgroup membership of the points is not re-checked here. It is
    /// guaranteed by the checked constructors and checked deserialization of
    /// the point wrappers (see [`PointWrapper`]).
    fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: TinySuite> Prover<S> for Secret<S> {
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let (t, io) = vrf_transcript::<S>(self.public.0, ios, ad);

        let mut k = S::nonce(&self.scalar, t.clone());

        // R = k * I_m
        let r = smul!(io.input.0, k).into_affine();

        let c = S::challenge(&[&r], t);
        let mut cx = c * self.scalar;
        let s = k + cx;
        k.zeroize();
        cx.zeroize();
        Proof { c, s }
    }
}

impl<S: TinySuite> Verifier<S> for Public<S> {
    fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        // With Y = 0 the challenge term drops out of the equation below and
        // anyone can produce a matching (c, s) pair.
        if self.is_identity() {
            return Err(Error::InvalidData);
        }

        // A pair holding the identity satisfies O = x*I for every x, so it
        // binds its VRF output to no signer.
        let ios = ios.as_ref();
        if ios.iter().any(VrfIo::has_identity) {
            return Err(Error::InvalidData);
        }

        let (t, io) = vrf_transcript::<S>(self.0, ios, ad);

        let Proof { c, s } = proof;

        // R = s * I_m - c * O_m
        let r = short_msm(&[io.input.0, io.output.0], &[*s, -*c], 2).into_affine();

        let c_exp = S::challenge(&[&r], t);
        (c_exp == *c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::testing::{self as common, SuiteExt};

    pub fn prove_verify<S: TinySuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(common::random_val(None));
        let io = secret.vrf_io(input);

        let proof = secret.prove(io, b"foo");
        let result = public.verify(io, b"foo", &proof);
        assert!(result.is_ok());
    }

    pub fn prove_verify_multi_empty<S: TinySuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();

        let ios: [VrfIo<S>; 0] = [];
        let proof = secret.prove(ios, b"bar");

        assert!(public.verify(ios, b"bar", &proof).is_ok());

        // Wrong ad should fail
        assert!(public.verify(ios, b"baz", &proof).is_err());
    }

    /// N=1 slice produces same proof as passing a single `VrfIo`.
    pub fn prove_verify_multi_single<S: TinySuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(common::random_val(None));
        let io = secret.vrf_io(input);

        let proof_single = secret.prove(io, b"foo");
        let proof_slice = secret.prove([io], b"foo");

        // Byte-identical proofs
        let encode = |p: &tiny::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));

        // Cross-verification
        assert!(public.verify(io, b"foo", &proof_slice).is_ok());
        assert!(public.verify([io], b"foo", &proof_single).is_ok());
    }

    /// An identity public key must be rejected by the verifier.
    ///
    /// `Y = 0` is the public key of the zero secret key, which everybody knows,
    /// so the proof built below is one any attacker can build. Verification is
    /// handed a raw `Public` to make sure the rejection does not depend on the
    /// key having gone through a checked constructor.
    pub fn identity_public_key_rejected<S: TinySuite>() {
        let identity = Public::<S>::from_affine_unchecked(AffinePoint::<S>::zero());
        let zero_secret = Secret::<S>::from_scalar(ScalarField::<S>::zero());

        let proof = zero_secret.prove([], b"forgery");
        assert!(identity.verify([], b"forgery", &proof).is_err());
    }

    /// An I/O pair holding the identity must be rejected by the verifier.
    ///
    /// `(I, O) = (0, 0)` satisfies `O = x * I` for every secret key, so the
    /// verification equation accepts it and two different keys produce two
    /// valid proofs for the same pair. The pair therefore binds its VRF output
    /// to nobody, and only an explicit check keeps it out. The second case
    /// hides the bad pair behind a good one, where the merged pair alone is not
    /// enough to catch it.
    pub fn identity_io_pair_rejected<S: TinySuite>() {
        let identity_io = VrfIo::<S> {
            input: Input::from_affine_unchecked(AffinePoint::<S>::zero()),
            output: Output::from_affine_unchecked(AffinePoint::<S>::zero()),
        };

        for seed in [common::TEST_SEED, [0x11; 32]] {
            let secret = Secret::<S>::from_seed(seed);
            let public = secret.public();

            let proof = secret.prove([identity_io], b"forgery");
            assert!(public.verify([identity_io], b"forgery", &proof).is_err());

            let good_io = secret.vrf_io(Input::new(b"good").unwrap());
            let ios = [good_io, identity_io];
            let proof = secret.prove(ios, b"forgery");
            assert!(public.verify(ios, b"forgery", &proof).is_err());
        }
    }

    /// N=3 multi proof: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: TinySuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();

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

        let proof = secret.prove(&ios[..], b"bar");
        assert!(public.verify(&ios[..], b"bar", &proof).is_ok());

        // Tamper: wrong output on ios[1]
        let mut bad_ios = ios.clone();
        bad_ios[1].output = secret.output(ios[0].input);
        assert!(public.verify(&bad_ios[..], b"bar", &proof).is_err());

        // Tamper: wrong input on ios[0]
        let mut bad_ios = ios.clone();
        bad_ios[0].input = ios[1].input;
        assert!(public.verify(&bad_ios[..], b"bar", &proof).is_err());

        // Tamper: wrong ad
        assert!(public.verify(&ios[..], b"baz", &proof).is_err());
    }

    /// `merge_ios` switches to its MSM branch at `MSM_THRESHOLD` pairs. This
    /// runs the branch through prove and verify; the branch itself is checked
    /// against a plain sum in `utils::common`.
    pub fn prove_verify_multi_msm<S: TinySuite>() {
        use crate::utils::common::MSM_THRESHOLD;

        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let ios: Vec<VrfIo<S>> = (0..MSM_THRESHOLD as u8)
            .map(|i| secret.vrf_io(Input::new(&[i]).unwrap()))
            .collect();

        let proof = secret.prove(&ios[..], b"msm");
        assert!(public.verify(&ios[..], b"msm", &proof).is_ok());

        // Tamper: wrong output on the last pair
        let mut bad_ios = ios.clone();
        bad_ios[MSM_THRESHOLD - 1].output = ios[0].output;
        assert!(public.verify(&bad_ios[..], b"msm", &proof).is_err());
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
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, ad);
            let io = VrfIo {
                input: Input::from_affine_unchecked(base.h),
                output: Output::from_affine_unchecked(base.gamma),
            };
            let sk = Secret::from_scalar(base.sk);
            let proof: Proof<S> = sk.prove(io, ad);
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
            let io = VrfIo {
                input: Input::<S>::from_affine_unchecked(self.base.h),
                output: Output::from_affine_unchecked(self.base.gamma),
            };
            let sk = Secret::from_scalar(self.base.sk);
            let proof = sk.prove(io, &self.base.ad);
            assert_eq!(self.c, proof.c, "VRF proof challenge ('c') mismatch");
            assert_eq!(self.s, proof.s, "VRF proof response ('s') mismatch");

            let pk = Public::<S>::from_affine_unchecked(self.base.pk);
            assert!(pk.verify(io, &self.base.ad, &proof).is_ok());
        }
    }

    /// `Suite::SECURITY_PARAMETER` sizes the challenge and the Tiny encoding
    /// of it: a suite at 256 bits writes `c` on 32 bytes and reads it back.
    #[test]
    fn challenge_encoding_follows_security_parameter() {
        use crate::suites::testing::TestSuite256 as S;

        assert_eq!(S::CHALLENGE_LEN, 32);
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let io = secret.vrf_io(Input::new(b"wide").unwrap());
        let proof = secret.prove(io, b"ad");
        let c_bytes = common::scalar_encode::<S>(&proof.c);
        assert!(c_bytes[16..].iter().any(|byte| *byte != 0));

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes.len(), proof.compressed_size());
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(public.verify(io, b"ad", &decoded).is_ok());
    }

    /// `Suite::CHALLENGE_LEN` may exceed the level, up to the scalar width.
    /// At the full width a byte string at or above the field order reduces
    /// to a valid `c`, so the decoder must reject it: one proof, one encoding.
    #[test]
    fn challenge_len_can_exceed_the_level() {
        use crate::suites::testing::TestSuiteC32 as S;
        use ark_ff::BigInteger;

        assert_eq!(S::SECURITY_PARAMETER, 128);
        assert_eq!(S::CHALLENGE_LEN, 32);
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let io = secret.vrf_io(Input::new(b"wide").unwrap());
        let proof = secret.prove(io, b"ad");
        let c_bytes = common::scalar_encode::<S>(&proof.c);
        assert!(c_bytes[16..].iter().any(|byte| *byte != 0));

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64);
        let decoded = Proof::<S>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(public.verify(io, b"ad", &decoded).is_ok());

        let mut alias = proof.c.into_bigint();
        assert!(!alias.add_with_carry(&ScalarField::<S>::MODULUS));
        bytes[..32].copy_from_slice(&alias.to_bytes_le());
        assert!(Proof::<S>::deserialize_compressed(&bytes[..]).is_err());
        assert!(Proof::<S>::deserialize_compressed_unchecked(&bytes[..]).is_err());
    }
}
