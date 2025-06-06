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
//! let input = Input::from(my_data);
//! let output = secret.output(input);
//! let proof = secret.prove(input, output, aux_data);
//!
//! // Verification
//! use ark_vrf::ietf::Verifier;
//! let result = public.verify(input, output, aux_data, &proof);
//! ```

use super::*;

pub trait IetfSuite: Suite {}

impl<T> IetfSuite for T where T: Suite {}

/// IETF VRF proof.
///
/// Schnorr-based proof of correctness for a VRF evaluation:
/// - `c`: Challenge scalar derived from public parameters
/// - `s`: Response scalar satisfying the verification equation
#[derive(Debug, Clone)]
pub struct Proof<S: IetfSuite> {
    pub c: ScalarField<S>,
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
            return Err(ark_serialize::SerializationError::NotEnoughSpace);
        }
        let buf = if S::Codec::BIG_ENDIAN {
            &c_buf[c_buf.len() - S::CHALLENGE_LEN..]
        } else {
            &c_buf[..S::CHALLENGE_LEN]
        };
        writer.write_all(buf)?;
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
    /// Generate a proof for the given input/output and additional data.
    ///
    /// Creates a non-interactive zero-knowledge proof binding the input, output,
    /// and additional data to the prover's public key.
    ///
    /// * `input` - VRF input point
    /// * `output` - VRF output point (γ = x·H)
    /// * `ad` - Additional data to bind to the proof
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

/// Trait for entities that can verify VRF proofs.
///
/// Implementors can verify that a VRF output is correctly derived
/// from an input using a specific public key.
pub trait Verifier<S: IetfSuite> {
    /// Verify a proof for the given input/output and additional data.
    ///
    /// Verifies the cryptographic relationship between input, output, and proof
    /// under the verifier's public key.
    ///
    /// * `input` - VRF input point
    /// * `output` - Claimed VRF output point
    /// * `aux` - Additional data bound to the proof
    /// * `proof` - The proof to verify
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(Error::VerificationFailure)` otherwise.
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
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
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let k = S::nonce(&self.scalar, input);

        let k_b = smul!(S::generator(), k).into_affine();
        let k_h = smul!(input.0, k).into_affine();

        let c = S::challenge(
            &[&self.public.0, &input.0, &output.0, &k_b, &k_h],
            ad.as_ref(),
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
        input: Input<S>,
        output: Output<S>,
        aux: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof { c, s } = proof;

        let s_b = S::generator() * s;
        let c_y = self.0 * c;
        let u = (s_b - c_y).into_affine();

        let s_h = input.0 * s;
        let c_o = output.0 * c;
        let v = (s_h - c_o).into_affine();

        let c_exp = S::challenge(&[&self.0, &input.0, &output.0, &u, &v], aux.as_ref());
        (&c_exp == c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::testing::{self as common, SuiteExt};

    pub fn prove_verify<S: IetfSuite>() {
        use ietf::{Prover, Verifier};

        let secret = Secret::<S>::from_seed(common::TEST_SEED);
        let public = secret.public();
        let input = Input::from(common::random_val(None));
        let output = secret.output(input);

        let proof = secret.prove(input, output, b"foo");
        let result = public.verify(input, output, b"foo", &proof);
        assert!(result.is_ok());
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
            // TODO: store constructed types in the vectors
            let input = Input::from(base.h);
            let output = Output::from(base.gamma);
            let sk = Secret::from_scalar(base.sk);
            let proof: Proof<S> = sk.prove(input, output, ad);
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
            let proof_c = if S::Codec::BIG_ENDIAN {
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
            let input = Input::<S>::from(self.base.h);
            let output = Output::from(self.base.gamma);
            let sk = Secret::from_scalar(self.base.sk);
            let proof = sk.prove(input, output, &self.base.ad);
            assert_eq!(self.c, proof.c, "VRF proof challenge ('c') mismatch");
            assert_eq!(self.s, proof.s, "VRF proof response ('s') mismatch");

            let pk = Public(self.base.pk);
            assert!(pk.verify(input, output, &self.base.ad, &proof).is_ok());
        }
    }
}
