//! Suite for testing

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"Testing_SHA-256_TAI";
    const CHALLENGE_LEN: usize = 16;

    // TODO: babyjubjub?
    type Affine = ark_ed25519::EdwardsAffine;
    type Hasher = sha2::Sha256;
    type Codec = codec::ArkworksCodec;

    fn data_to_point(data: &[u8]) -> Option<crate::AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }

    fn nonce(sk: &ScalarField, pts: &[&AffinePoint], ad: &[u8]) -> ScalarField
    where
        Self: Suite,
        Self::Codec: codec::Codec<Self>,
    {
        use digest::Digest;
        let mut buf = Vec::with_capacity(
            <Self::Codec as codec::Codec<Self>>::SCALAR_ENCODED_LEN
                + <Self::Codec as codec::Codec<Self>>::POINT_ENCODED_LEN,
        );
        <Self::Codec as codec::Codec<Self>>::scalar_encode_into(sk, &mut buf);
        for pt in pts {
            <Self::Codec as codec::Codec<Self>>::point_encode_into(pt, &mut buf);
        }
        let h = Self::Hasher::new()
            .chain_update(&buf)
            .chain_update(ad)
            .finalize();
        <Self::Codec as codec::Codec<Self>>::scalar_decode(&h)
    }

    fn challenge(pts: &[&crate::AffinePoint<Self>], ad: &[u8]) -> crate::ScalarField<Self> {
        utils::challenge_rfc_9381::<Self>(pts, ad)
    }

    fn point_to_hash(pt: &crate::AffinePoint<Self>) -> crate::HashOutput<Self> {
        utils::point_to_hash_rfc_9381::<Self>(pt, false)
    }
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "22908039810913044136917741489726647027277366293258891749889809241450460853949"
        );
        const Y: BaseField = MontFp!(
            "49264587079666684025030007335154795146762108024019949463673115011651474636151"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);

impl crate::testing::SuiteExt for TestSuite {}

#[cfg(test)]
mod tests {
    use super::*;
    codec_suite_tests!(TestSuite);
    ietf_suite_tests!(TestSuite);
    pedersen_suite_tests!(TestSuite);
    thin_suite_tests!(TestSuite);
}
