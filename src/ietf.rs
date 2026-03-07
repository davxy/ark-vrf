//! # IETF-VRF
//!
//! Implementation of the ECVRF scheme defined in [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//! extended to support binding additional data to the proof.
//!
//! The extension specification is available at:
//! <https://github.com/davxy/bandersnatch-vrf-spec>
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! // Key generation
//! let secret = Secret::<MySuite>::from_seed(b"seed");
//! let public = secret.public();
//!
//! // Proving
//! use ark_vrf::ietf::Prover;
//! let input = Input::from_affine(my_data);
//! let io = secret.vrf_io(input);
//! let proof = secret.prove(io, aux_data);
//!
//! // Verification
//! use ark_vrf::ietf::Verifier;
//! let result = public.verify(io, aux_data, &proof);
//! ```

use super::*;

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
        let c_buf = codec::scalar_encode::<S>(&self.c);
        if c_buf.len() < S::CHALLENGE_LEN {
            // Encoded scalar length must be at least S::CHALLENGE_LEN
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let (c, zero) = if S::Codec::ENDIANNESS.is_little() {
            c_buf.split_at(S::CHALLENGE_LEN)
        } else {
            let (high, low) = c_buf.split_at(c_buf.len() - S::CHALLENGE_LEN);
            (low, high)
        };
        if zero.iter().any(|&b| b != 0) {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        writer.write_all(c)?;
        self.s.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, _compress_always: ark_serialize::Compress) -> usize {
        S::CHALLENGE_LEN + self.s.compressed_size()
    }
}

impl<S: IetfSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut c_buf = ark_std::vec![0; S::CHALLENGE_LEN];
        if reader.read_exact(&mut c_buf[..]).is_err() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let c = S::Codec::scalar_decode(&c_buf);
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

/// Trait for types that can generate VRF proofs.
///
/// Implementors can create cryptographic proofs that a VRF output
/// is correctly derived from an input using their secret key.
pub trait Prover<S: IetfSuite> {
    /// Generate a proof for the given VRF I/O pairs and additional data.
    ///
    /// Creates a non-interactive zero-knowledge proof binding the input, output,
    /// and additional data to the prover's public key.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before proving.
    ///
    /// * `ios` - VRF input/output pairs
    /// * `ad` - Additional data to bind to the proof
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for entities that can verify VRF proofs.
///
/// Implementors can verify that a VRF output is correctly derived
/// from an input using a specific public key.
pub trait Verifier<S: IetfSuite> {
    /// Verify a proof for the given VRF I/O pairs and additional data.
    ///
    /// Verifies the cryptographic relationship between input, output, and proof
    /// under the verifier's public key.
    ///
    /// Multiple I/O pairs are delinearized into a single merged pair before verifying.
    ///
    /// * `ios` - VRF input/output pairs
    /// * `aux` - Additional data bound to the proof
    /// * `proof` - The proof to verify
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
    /// This follows the procedure specified in RFC-9381 section 5.1, with extensions
    /// to support binding additional data to the proof:
    ///
    /// 1. Generate a deterministic nonce `k` based on the secret key and input
    /// 2. Compute nonce commitments `k_b` and `k_h`
    /// 3. Compute the challenge `c` using all public values, nonce commitments and the
    ///    additional data
    /// 4. Compute the response `s = k + c * secret`
    ///
    /// **Deviation from RFC 9381:** The nonce derivation includes the output point
    /// alongside the input, whereas the RFC only uses the input. Since `prove`
    /// receives pre-computed outputs rather than recomputing them internally, this
    /// binds the nonce to the specific output, preventing nonce reuse if different
    /// outputs are ever provided for the same `(secret, input, ad)` tuple — which
    /// would otherwise enable secret key recovery. The resulting proof remains
    /// compatible with RFC 9381 verification.
    fn prove(&self, ios: impl AsRef<[VrfIo<S>]>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let ad = ad.as_ref();
        let t = S::Transcript::new(S::SUITE_ID);
        let (input, output) = utils::delinearize(ios.as_ref().iter().copied(), ad, Some(t.clone()));

        let k = S::nonce(&self.scalar, &[&input.0, &output.0], ad);

        let k_b = smul!(S::generator(), k);
        let k_h = smul!(input.0, k);
        let norms = CurveGroup::normalize_batch(&[k_b, k_h]);
        let (k_b, k_h) = (norms[0], norms[1]);

        let c = S::challenge(
            &[&self.public.0, &input.0, &output.0, &k_b, &k_h],
            ad,
            Some(t),
        );
        let s = k + c * self.scalar;
        Proof { c, s }
    }
}

impl<S: IetfSuite> Verifier<S> for Public<S> {
    /// Implements the IETF VRF verification algorithm.
    ///
    /// This follows the procedure specified in RFC-9381 section 5.3, with extensions
    /// to support verifying additional data bound to the proof:
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
        let aux = aux.as_ref();
        let t = S::Transcript::new(S::SUITE_ID);
        let (input, output) = utils::delinearize(ios.as_ref().iter().copied(), ad, Some(t.clone()));

        let Proof { c, s } = proof;

        let u = S::generator() * s - self.0 * c;
        let v = input.0 * s - output.0 * c;
        let norms = CurveGroup::normalize_batch(&[u, v]);
        let (u, v) = (norms[0], norms[1]);

        let c_exp = S::challenge(&[&self.0, &input.0, &output.0, &u, &v], ad, Some(t));
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
        let input = Input::from_affine(common::random_val(None));
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
        let input = Input::from_affine(common::random_val(None));
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
            let c = hex::encode(codec::scalar_encode::<S>(&self.c));
            let s = hex::encode(codec::scalar_encode::<S>(&self.s));
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
            S::suite_name() + "_ietf"
        }

        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, salt, ad);
            let io = VrfIo {
                input: Input::from_affine(base.h),
                output: Output::from_affine(base.gamma),
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
            let c = S::Codec::scalar_decode(&map.get_bytes("proof_c"));
            let s = S::Codec::scalar_decode(&map.get_bytes("proof_s"));
            Self { base, c, s }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let buf = codec::scalar_encode::<S>(&self.c);
            let proof_c = if S::Codec::ENDIANNESS.is_big() {
                let len = buf.len();
                &buf[len - S::CHALLENGE_LEN..]
            } else {
                &buf[..S::CHALLENGE_LEN]
            };
            let items = [
                ("proof_c", hex::encode(proof_c)),
                ("proof_s", hex::encode(codec::scalar_encode::<S>(&self.s))),
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
                input: Input::<S>::from_affine(self.base.h),
                output: Output::from_affine(self.base.gamma),
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
