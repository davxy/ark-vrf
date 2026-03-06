//! ECVRF Baby-JubJub SHA-512 TAI suite
//!
//! Configuration:
//!
//! * `suite_string` = b"Baby-JubJub_SHA-512_TAI".
//!
//! - The EC group **G** is the prime subgroup of the Baby-JubJub elliptic curve
//!   as defined by <https://github.com/barryWhiteHat/baby_jubjub>.
//!   For this group, `fLen` = `qLen` = $32$ and `cofactor` = $8$.
//!
//! - The prime subgroup generator G is defined as follows:
//!   - G.x = 19698561148652590122159747500897617769866003486955115824547446575314762165298
//!   - G.y = 19298250018296453272277890825869354524455968081175474282777126169995084727839
//!
//! * `cLen` = 16. As prescribed by RFC-9381 section 5.5 for curves with
//!   approximately 128-bit security level.
//!
//! * The key pair generation primitive is `PK = sk * G`, with x the secret
//!   key scalar and `G` the group generator. In this ciphersuite, the secret
//!   scalar x is equal to the secret key scalar sk.
//!
//! * The ECVRF_nonce_generation function is as specified in Section 5.4.2.2
//!   of RFC-9381.
//!
//! * The int_to_string function encodes into the 32 bytes little endian
//!   representation.
//!
//! * The string_to_int function decodes from the 32 bytes little endian
//!   representation.
//!
//! * The point_to_string function converts a point in **G** to an octet
//!   string using compressed form. The y coordinate is encoded using
//!   int_to_string function and the most significant bit of the last
//!   octet is used to keep track of the x's sign. This implies that
//!   the point is encoded on 32 bytes.
//!
//! * The string_to_point function tries to decompress the point encoded
//!   according to `point_to_string` procedure. This function MUST outputs
//!   "INVALID" if the octet string does not decode to a point on G.
//!
//! * The hash function Hash is SHA-512 as specified in
//!   [RFC6234](https://www.rfc-editor.org/rfc/rfc6234), with hLen = 64.
//!
//! * The `ECVRF_encode_to_curve` function uses try and increment.
//!   as defined by RFC 9381 section 5.4.1.1.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabyJubJubSha512Ell2;

type ThisSuite = BabyJubJubSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Baby-JubJub_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed_on_bn254::EdwardsAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;

    fn data_to_point(data: &[u8]) -> Option<crate::AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }

    fn nonce(sk: &ScalarField, pts: &[&AffinePoint], ad: &[u8]) -> ScalarField {
        utils::nonce_rfc_8032::<Self>(sk, pts, ad)
    }

    fn challenge(pts: &[&AffinePoint], ad: &[u8]) -> ScalarField {
        utils::challenge_rfc_9381::<Self>(pts, ad)
    }

    fn point_to_hash(pt: &AffinePoint) -> crate::HashOutput<Self> {
        utils::point_to_hash_rfc_9381::<Self>(pt, false)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("6048199350074762559032156900146814122791817523678289748284553613712420417431");
        const Y: BaseField = MontFp!(
            "12186328959432421529225823682482646446555889239136070923512221343464169861724"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bn254::Bn254;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("4475972259506354389975346640188250838283218622830205159006266389543265313642");
        const Y: BaseField = MontFp!(
            "14355656911833297441422784025671851197003981290736405920038347763508319562994"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "14575782461834592606737113966358928183410848165019884014303605687191346327082"
        );
        const Y: BaseField =
            MontFp!("20552501344568544113500096043766045502502610147034855921693534989361843836186");
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {}

    codec_suite_tests!(ThisSuite);
    ietf_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BN254_PCS_SRS_FILE;

        fn params() -> &'static RingProofParams {
            use std::sync::OnceLock;
            static PARAMS: OnceLock<RingProofParams> = OnceLock::new();
            PARAMS.get_or_init(Self::load_context)
        }
    }
}
