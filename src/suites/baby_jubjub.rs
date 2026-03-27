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
//! * `cLen` = 16 (128-bit security level).
//!
//! * The key pair generation primitive is `PK = sk * G`, with x the secret
//!   key scalar and `G` the group generator. In this ciphersuite, the secret
//!   scalar x is equal to the secret key scalar sk.
//!
//! * Nonce generation is inspired by Section 5.4.2.2 of RFC-9381,
//!   adapted to use the suite's pluggable transcript.
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
//! * The `ECVRF_encode_to_curve` function uses Try-And-Increment, inspired
//!   by Section 5.4.1.1 of RFC-9381.

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabyJubJubSha512Ell2;

type ThisSuite = BabyJubJubSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::BABY_JUBJUB, hash::SHA512, h2c::TAI);
    type Affine = ark_ed_on_bn254::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("3852734544355356063317634488002685979020112825255449618227510301364760062073");
        const Y: BaseField = MontFp!(
            "17088278391043382496921486048141624342867409190109151642986824185616238928969"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bn254::Bn254;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "11664680487321917236097530868803259071263990200760487324140232667602003433219"
        );
        const Y: BaseField =
            MontFp!("113063537817015047906997614658008886559348806974485740897143643717788516825");
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "15741539849944168260188760383525647014748560733999604648188402080866721960158"
        );
        const Y: BaseField = MontFp!(
            "15704905423721781544793327059143155781918240455118260763073886055868852392633"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {
        const SUITE_NAME: &str = "baby-jubjub_sha-512_tai";
    }

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
