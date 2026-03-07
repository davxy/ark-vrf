//! Points and scalars encoding.
//!
//! Little-endian arkworks serialization with compression enabled.

use ark_ec::short_weierstrass::SWCurveConfig;

use super::*;

/// Number of flag bits used in arkworks compressed point serialization.
///
/// Twisted Edwards curves use 1 bit (x-coordinate sign).
/// Short Weierstrass curves use 2 bits (infinity + y-coordinate sign).
pub trait CompressFlagBits {
    const FLAG_BITS: u32;
}

impl<P: ark_ec::twisted_edwards::TECurveConfig> CompressFlagBits
    for ark_ec::twisted_edwards::Affine<P>
{
    const FLAG_BITS: u32 = 1;
}

impl<P: SWCurveConfig> CompressFlagBits for ark_ec::short_weierstrass::Affine<P> {
    const FLAG_BITS: u32 = 2;
}

/// Point compressed encoded length in bytes.
///
/// Matches arkworks' `serialized_size_with_flags`:
/// `ceil((MODULUS_BIT_SIZE + FLAG_BITS) / 8)`.
pub const fn point_encoded_len<S: Suite>() -> usize
where
    BaseField<S>: PrimeField,
    AffinePoint<S>: CompressFlagBits,
{
    (BaseField::<S>::MODULUS_BIT_SIZE as usize + AffinePoint::<S>::FLAG_BITS as usize).div_ceil(8)
}

/// Scalar compressed encoded length in bytes.
pub const fn scalar_encoded_len<S: Suite>() -> usize {
    (ScalarField::<S>::MODULUS_BIT_SIZE as usize).div_ceil(8)
}

/// Point encode.
pub fn point_encode<S: Suite>(pt: &AffinePoint<S>) -> Vec<u8> {
    let mut buf = Vec::new();
    pt.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Point decode.
pub fn point_decode<S: Suite>(buf: &[u8]) -> Result<AffinePoint<S>, Error> {
    AffinePoint::<S>::deserialize_compressed_unchecked(buf).map_err(Into::into)
}

/// Scalar encode.
pub fn scalar_encode<S: Suite>(sc: &ScalarField<S>) -> Vec<u8> {
    let mut buf = Vec::new();
    sc.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Scalar decode.
pub fn scalar_decode<S: Suite>(buf: &[u8]) -> ScalarField<S> {
    ScalarField::<S>::from_le_bytes_mod_order(buf)
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::testing::TEST_SEED;

    pub fn encoded_lengths<S: Suite>()
    where
        BaseField<S>: PrimeField,
        AffinePoint<S>: CompressFlagBits,
    {
        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();

        let point_buf = point_encode::<S>(&public.0);
        let expected_pt = point_encoded_len::<S>();
        assert_eq!(
            point_buf.len(),
            expected_pt,
            "POINT_ENCODED_LEN mismatch: const {} vs actual {}",
            expected_pt,
            point_buf.len(),
        );

        let scalar_buf = scalar_encode::<S>(&secret.scalar);
        let expected_sc = scalar_encoded_len::<S>();
        assert_eq!(
            scalar_buf.len(),
            expected_sc,
            "SCALAR_ENCODED_LEN mismatch: const {} vs actual {}",
            expected_sc,
            scalar_buf.len(),
        );
    }

    pub fn roundtrip<S: Suite>() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        let secret = Secret::<S>::from_seed(TEST_SEED);

        let mut buf = Vec::new();
        secret.serialize_compressed(&mut buf).unwrap();
        let secret2 = Secret::<S>::deserialize_compressed(&mut &buf[..]).unwrap();
        assert_eq!(secret.scalar, secret2.scalar);

        let mut buf = Vec::new();
        let public = secret.public();
        public.serialize_compressed(&mut buf).unwrap();
        let public2 = Public::<S>::deserialize_compressed(&mut &buf[..]).unwrap();
        assert_eq!(public.0, public2.0);
    }

    #[macro_export]
    macro_rules! codec_suite_tests {
        ($suite:ty) => {
            mod codec {
                use super::*;

                #[test]
                fn encoded_lengths() {
                    $crate::codec::testing::encoded_lengths::<$suite>();
                }

                #[test]
                fn roundtrip() {
                    $crate::codec::testing::roundtrip::<$suite>();
                }
            }
        };
    }
}
