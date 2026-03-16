//! # IETF-VRF
//!
//! ECVRF implementation based on [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//! with a pluggable transcript-based Fiat-Shamir transform and support for
//! binding additional data to the proof.
//!
//! The specification is available at:
//! <https://github.com/davxy/bandersnatch-vrf-spec>
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! // Key generation
//! let secret = Secret::<MySuite>::from_seed([0; 32]);
//! let public = secret.public();
//!
//! // Proving
//! use ark_vrf::ietf::Prover;
//! let input = Input::from_affine_unchecked(my_data);
//! let io = secret.vrf_io(input);
//! let proof = secret.prove(io, aux_data);
//!
//! // Verification
//! use ark_vrf::ietf::Verifier;
//! let result = public.verify(io, aux_data, &proof);
//! ```

use super::*;
use utils::common::DomSep;

/// Marker trait for suites that support the IETF VRF scheme.
///
/// Blanket-implemented for all types implementing [`Suite`].
pub trait IetfSuite: Suite {}

impl<T> IetfSuite for T where T: Suite {}

/// IETF VRF proof.
///
/// Schnorr-based proof of correctness for a VRF evaluation:
/// - `c`: Challenge scalar derived from public parameters
/// - `s`: Response scalar satisfying the verification equation
#[derive(Debug, Clone)]
pub struct Proof<S: IetfSuite> {
    /// Challenge scalar derived from public parameters.
    pub c: ScalarField<S>,
    /// Response scalar satisfying the verification equation.
    pub s: ScalarField<S>,
}

impl<S: IetfSuite> CanonicalSerialize for Proof<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let scalar_len = ScalarField::<S>::MODULUS_BIT_SIZE.div_ceil(8) as usize;
        if scalar_len < utils::common::CHALLENGE_LEN {
            // Encoded scalar length must be at least utils::common::CHALLENGE_LEN
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut c_buf = [0; 128];
        self.c
            .serialize_compressed(&mut c_buf[..])
            .expect("c_buf is big enough");
        let c_buf = &c_buf[..utils::common::CHALLENGE_LEN];
        writer.write_all(c_buf)?;
        self.s.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        utils::common::CHALLENGE_LEN + self.s.serialized_size(compress)
    }
}

impl<S: IetfSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut c_buf = [0u8; utils::common::CHALLENGE_LEN];
        if reader.read_exact(&mut c_buf[..]).is_err() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let c = ScalarField::<S>::from_le_bytes_mod_order(&c_buf);
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        Ok(Proof { c, s })
    }
}

impl<S: IetfSuite> ark_serialize::Valid for Proof<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.c.check()?;
        self.s.check()?;
        Ok(())
    }
}

/// Trait for types that can generate IETF VRF proofs.
pub trait Prover<S: IetfSuite> {
    /// Generate a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before proving.
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for entities that can verify IETF VRF proofs.
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
pub trait Verifier<S: IetfSuite> {
    /// Verify a proof for the given VRF I/O pairs and additional data.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before verifying.
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::VerificationFailure)` otherwise.
    fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        aux: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: IetfSuite> Prover<S> for Secret<S> {
    /// Implements the IETF VRF proving algorithm.
    ///
    /// Based on the procedure in RFC-9381 section 5.1, adapted to use a
    /// transcript-based Fiat-Shamir transform and support for additional data:
    ///
    /// 1. Generate a deterministic nonce `k` based on the secret key and input
    /// 2. Compute nonce commitments `k_b` and `k_h`
    /// 3. Compute the challenge `c` using all public values, nonce commitments and the
    ///    additional data
    /// 4. Compute the response `s = k + c * secret`
    ///
    /// The nonce derivation includes the output point alongside the input. Since
    /// `prove` receives pre-computed outputs rather than recomputing them internally,
    /// this binds the nonce to the specific output, preventing nonce reuse if
    /// different outputs are ever provided for the same `(secret, input, ad)` tuple
    /// — which would otherwise enable secret key recovery.
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let (t, io) = utils::vrf_transcript(DomSep::IetfVrf, ios, ad);

        let k = S::nonce(&self.scalar, Some(t.clone()));

        let k_b = smul!(S::generator(), k);
        let k_h = smul!(io.input.0, k);
        let norms = CurveGroup::normalize_batch(&[k_b, k_h]);
        let (k_b, k_h) = (norms[0], norms[1]);

        let c = S::challenge(&[&self.public.0, &k_b, &k_h], Some(t));
        let s = k + c * self.scalar;
        Proof { c, s }
    }
}

impl<S: IetfSuite> Verifier<S> for Public<S> {
    /// Implements the IETF VRF verification algorithm.
    ///
    /// Based on the procedure in RFC-9381 section 5.3, adapted to use a
    /// transcript-based Fiat-Shamir transform and support for additional data:
    ///
    /// 1. Compute `u = s*G - c*Y` where G is the generator and Y is the public key
    /// 2. Compute `v = s*H - c*O` where H is the input point and O is the output point
    /// 3. Recompute the expected challenge `c_exp` using all public values, `u`, `v` and
    ///    the additional data
    /// 4. Verify that `c_exp == c` from the proof
    fn verify(
        &self,
        ios: impl AsRef<[VrfIo<S>]>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let (t, io) = utils::vrf_transcript(DomSep::IetfVrf, ios, ad);

        let Proof { c, s } = proof;

        let u = S::generator() * s - self.0 * c;
        let v = io.input.0 * s - io.output.0 * c;
        let norms = CurveGroup::normalize_batch(&[u, v]);
        let (u, v) = (norms[0], norms[1]);

        let c_exp = S::challenge(&[&self.0, &u, &v], Some(t));
        (c_exp == *c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::testing::{self as common, SuiteExt};

    pub fn prove_verify<S: IetfSuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(common::random_val(None));
        let io = secret.vrf_io(input);

        let proof = secret.prove(io, b"foo");
        let result = public.verify(io, b"foo", &proof);
        assert!(result.is_ok());
    }

    pub fn prove_verify_multi_empty<S: IetfSuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();

        let ios: [VrfIo<S>; 0] = [];
        let proof = secret.prove(ios, b"bar");

        assert!(public.verify(ios, b"bar", &proof).is_ok());

        // Wrong ad should fail
        assert!(public.verify(ios, b"baz", &proof).is_err());
    }

    /// N=1 slice produces same proof as passing a single `VrfIo`.
    pub fn prove_verify_multi_single<S: IetfSuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from_affine_unchecked(common::random_val(None));
        let io = secret.vrf_io(input);

        let proof_single = secret.prove(io, b"foo");
        let proof_slice = secret.prove([io], b"foo");

        // Byte-identical proofs
        let encode = |p: &ietf::Proof<S>| {
            let mut buf = Vec::new();
            p.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert_eq!(encode(&proof_single), encode(&proof_slice));

        // Cross-verification
        assert!(public.verify(io, b"foo", &proof_slice).is_ok());
        assert!(public.verify([io], b"foo", &proof_single).is_ok());
    }

    /// N=3 multi proof: verify succeeds; tampered output/input/ad fails.
    pub fn prove_verify_multi<S: IetfSuite>() {
        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();

        let mut ios: Vec<VrfIo<S>> = (0..3u8)
            .map(|i| {
                let input = Input::new(&[i + 1]).unwrap();
                secret.vrf_io(input)
            })
            .collect();
        ios.push(VrfIo {
            input: Input(S::Affine::generator()),
            output: Output(public.0),
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

    #[macro_export]
    macro_rules! ietf_suite_tests {
        ($suite:ty) => {
            mod ietf {
                use super::*;

                #[test]
                fn prove_verify() {
                    $crate::ietf::testing::prove_verify::<$suite>();
                }

                #[test]
                fn prove_verify_multi_single() {
                    $crate::ietf::testing::prove_verify_multi_single::<$suite>();
                }

                #[test]
                fn prove_verify_multi() {
                    $crate::ietf::testing::prove_verify_multi::<$suite>();
                }

                #[test]
                fn prove_verify_multi_empty() {
                    $crate::ietf::testing::prove_verify_multi_empty::<$suite>();
                }

                $crate::test_vectors!($crate::ietf::testing::TestVector<$suite>);
            }
        };
    }

    pub struct TestVector<S: IetfSuite> {
        pub base: common::TestVector<S>,
        pub c: ScalarField<S>,
        pub s: ScalarField<S>,
    }

    impl<S: IetfSuite> core::fmt::Debug for TestVector<S> {
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
        S: IetfSuite + SuiteExt + std::fmt::Debug,
    {
        fn name() -> String {
            S::SUITE_NAME.to_string() + "_ietf"
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
            let proof_c = &buf[..utils::common::CHALLENGE_LEN];
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

            let pk = Public(self.base.pk);
            assert!(pk.verify(io, &self.base.ad, &proof).is_ok());
        }
    }
}
