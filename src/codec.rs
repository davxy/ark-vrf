//! Points and scalars encoding.
//!
//! Little-endian arkworks serialization with compression enabled.

use super::*;

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
                fn roundtrip() {
                    $crate::codec::testing::roundtrip::<$suite>();
                }
            }
        };
    }
}
