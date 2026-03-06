//! # ECVRF JubJub SHA-512 TAI suite
//!
//! Configuration:
//!
//! * `suite_string` = b"JubJub_SHA-512_TAI".
//!
//! - The EC group **G** is the prime subgroup of the JubJub elliptic curve
//!   as defined by <https://github.com/zkcrypto/jubjub>.
//!   For this group, `fLen` = `qLen` = $32$ and `cofactor` = $8$.
//!
//! - The prime subgroup generator G is defined as follows:
//!   - G.x = 8076246640662884909881801758704306714034609987455869804520522091855516602923
//!   - G.y = 13262374693698910701929044844600465831413122818447359594527400194675274060458
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
pub struct JubJubSha512Ell2;

type ThisSuite = JubJubSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"JubJub_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed_on_bls12_381::EdwardsAffine;
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
        const X: BaseField = MontFp!(
            "37791828864254608560512771045116976813822653252235145186847263146550774983573"
        );
        const Y: BaseField = MontFp!(
            "50281913639439767680904572037590409137260543547209066044189908038266865562866"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "50008126318621921789650212178911280404845722060756705823229864813583862671008"
        );
        const Y: BaseField = MontFp!(
            "41012592374371064331685030146264227241724139137619547652567048787727972666716"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "1579641385451470422997368464254681757635356627098777421858237888879067551015"
        );
        const Y: BaseField = MontFp!(
            "29815194172647243959461075220326959546380827704355488508192118227246739677800"
        );
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
        const SRS_FILE: &str = crate::testing::BLS12_381_PCS_SRS_FILE;

        fn params() -> &'static RingProofParams {
            use std::sync::OnceLock;
            static PARAMS: OnceLock<RingProofParams> = OnceLock::new();
            PARAMS.get_or_init(Self::load_context)
        }
    }
}
