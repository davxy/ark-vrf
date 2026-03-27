//! `ECVRF Bandersnatch-SW SHA-512 Try and Increment` suite.
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_SW_SHA-512_TAI" for Short Weierstrass form.
//!
//! - The EC group **G** is the prime subgroup of the Bandersnatch elliptic curve,
//!   in Short Weierstrass form, with finite field and curve parameters as specified in
//!   [MSZ21](https://eprint.iacr.org/2021/1152).
//!   For this group, `fLen` = `qLen` = $32$ and `cofactor` = $4$.
//!
//! - The prime subgroup generator G is defined as follows:
//!   - G.x = 30900340493481298850216505686589334086208278925799850409469406976849338430199
//!   - G.y = 12663882780877899054958035777720958383845500985908634476792678820121468453298
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
//! * The `ECVRF_encode_to_curve` function uses *Try and Increment*, inspired
//!   by section 5.4.1.1 of [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//!   with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_TAI_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, utils::te_sw_map::*, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Tai;

type ThisSuite = BandersnatchSha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::BANDERSNATCH_SW, hash::SHA512, h2c::TAI);
    type Affine = ark_ed_on_bls12_381_bandersnatch::SWAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "48417510423101441118061444208906839372921043480482028226883257289063255545370"
        );
        const Y: BaseField =
            MontFp!("605975869554501667057064844799976277818323013043881651153113184398732331110");
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "25211608582516829155149684046519409765416282531700259721714491517260527956556"
        );
        const Y: BaseField = MontFp!(
            "32863183837707411136510171551403506326134988374168040624784347522530012895695"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "46209466588428303799925407479102585354714183247629074296053567086083553831253"
        );
        const Y: BaseField = MontFp!(
            "46784016388819574388957654398028401259803727732223934061065126175128758725649"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

// sage: q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
// sage: Fq = GF(q)
// sage: MONT_A = 29978822694968839326280996386011761570173833766074948509196803838190355340952
// sage: MONT_B = 25465760566081946422412445027709227188579564747101592991722834452325077642517
// sage: MONT_A/Fq(3) = 9992940898322946442093665462003920523391277922024982836398934612730118446984
// sage: Fq(1)/MONT_B = 41180284393978236561320365279764246793818536543197771097409483252169927600582
impl MapConfig for ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig {
    const MONT_A_OVER_THREE: ark_ed_on_bls12_381_bandersnatch::Fq =
        MontFp!("9992940898322946442093665462003920523391277922024982836398934612730118446984");
    const MONT_B_INV: ark_ed_on_bls12_381_bandersnatch::Fq =
        MontFp!("41180284393978236561320365279764246793818536543197771097409483252169927600582");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ietf_suite_tests, testing};
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, SWAffine};

    impl crate::testing::SuiteExt for ThisSuite {
        const SUITE_NAME: &str = "bandersnatch_sw_sha-512_tai";
    }

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

    #[test]
    fn sw_to_te_roundtrip() {
        let roundtrip = |org_point| {
            let te_point = sw_to_te::<BandersnatchConfig>(&org_point).unwrap();
            assert!(te_point.is_on_curve());
            let sw_point = te_to_sw::<BandersnatchConfig>(&te_point).unwrap();
            assert!(sw_point.is_on_curve());
            assert_eq!(org_point, sw_point);
        };
        roundtrip(testing::random_val::<SWAffine>(None));
        roundtrip(AffinePoint::generator());
    }
}
