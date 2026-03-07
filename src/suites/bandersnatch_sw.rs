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
//! * The `ECVRF_encode_to_curve` function uses *Try and Increment* method described in
//!   described in section 5.4.1.1 of [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//!   with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_TAI_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use crate::{pedersen::PedersenSuite, utils::te_sw_map::*, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Tai;

type ThisSuite = BandersnatchSha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch_SW_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed_on_bls12_381_bandersnatch::SWAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
    type Codec = codec::ArkworksCodec;

    fn data_to_point(data: &[u8]) -> Option<crate::AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }

    fn nonce(
        sk: &ScalarField,
        transcript: Option<Self::Transcript>,
    ) -> ScalarField {
        utils::nonce_rfc_8032::<Self>(sk, transcript)
    }

    fn challenge(
        pts: &[&AffinePoint],
        transcript: Option<Self::Transcript>,
    ) -> ScalarField {
        utils::challenge_rfc_9381::<Self>(pts, transcript)
    }

    fn point_to_hash<const N: usize>(pt: &AffinePoint) -> [u8; N] {
        utils::point_to_hash_rfc_9381::<Self, N>(pt, false)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "19892242893588408382036028057788746585212827622991690890937387883100277593190"
        );
        const Y: BaseField =
            MontFp!("4109851282816960759929119884748338360037304870767368220353324005762376584513");
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "37737835654528811517316493208201743279686603225649422437125678949938434507743"
        );
        const Y: BaseField = MontFp!(
            "43514846826159324520031463615359243178393527180745703987165247944926352258649"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "36288045627234910453381927740135601478120109315183244154250860177022288854190"
        );
        const Y: BaseField = MontFp!(
            "37214065825235761174878258366942372586823525287345746235869898456349166039817"
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
