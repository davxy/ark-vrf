//! # ECVRF Bandersnatch SHA-512 Elligator2 suite
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_SHA-512_ELL2" for Twisted Edwards form.
//!
//! - The EC group **G** is the prime subgroup of the Bandersnatch elliptic curve,
//!   in Twisted Edwards form, with finite field and curve parameters as specified in
//!   [MSZ21](https://eprint.iacr.org/2021/1152).
//!   For this group, `fLen` = `qLen` = $32$ and `cofactor` = $4$.
//!
//! - The prime subgroup generator G is defined as follows:
//!   - G.x = 18886178867200960497001835917649091219057080094937609519140440539760939937304
//!   - G.y = 19188667384257783945677642223292697773471335439753913231509108946878080696678
//!
//! * `cLen` = 16 (128-bit security level).
//!
//! * The key pair generation primitive is _PK = sk * G_, with x the secret
//!   key scalar and G the group generator. In this ciphersuite, the secret
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
//! * The `ECVRF_encode_to_curve` function uses *Elligator2* method described in
//!   section 6.8.2 of [RFC-9380](https://datatracker.ietf.org/doc/rfc9380) and is
//!   described in section 5.4.1.2 of [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//!   with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_ELL2_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Ell2;

type ThisSuite = BandersnatchSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::BANDERSNATCH, hash::SHA512, h2c::ELL2);
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
    /// Hash data to a curve point using Elligator2 method described by RFC 9380.
    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        // "XMD" for expand_message_xmd (Section 5.3.1).
        // "RO" for random oracle (Section 3 - hash_to_curve method)
        let h2c_suite_id = b"Bandersnatch_XMD:SHA-512_ELL2_RO_";
        utils::hash_to_curve_ell2_xmd::<Self, sha2::Sha512>(data, h2c_suite_id)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("5226425992571220769365843487102064307101272980791993134273780736997544949382");
        const Y: BaseField = MontFp!(
            "46544868206883149332782258938702216106598247683423727002885664111567608220426"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "42303668360647658687880456753606405401141031996216729331450763906967498848487"
        );
        const Y: BaseField = MontFp!(
            "41898972259388202032055565840730004413653698329702630697317353721966090663285"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "29586100106858075217954567072572265001347911471605742544678436487322334776392"
        );
        const Y: BaseField = MontFp!(
            "21753411410084671346581650250322348778806357231808407562422401169820213423498"
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
        const SUITE_NAME: &str = "bandersnatch_sha-512_ell2";
    }

    tiny_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BLS12_381_PCS_SRS_FILE;

        fn ring_setup() -> &'static RingSetup {
            use std::sync::OnceLock;
            static RING_SETUP: OnceLock<RingSetup> = OnceLock::new();
            RING_SETUP.get_or_init(Self::load_ring_setup)
        }
    }

    #[test]
    fn elligator2_hash_to_curve() {
        use crate::testing::CheckPoint;
        let raw = crate::testing::random_vec(42, None);
        assert!(
            ThisSuite::data_to_point(&raw)
                .map(|p| p.check(true).ok())
                .is_some()
        );
    }
}
