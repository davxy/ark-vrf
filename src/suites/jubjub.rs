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
pub struct JubJubSha512Ell2;

type ThisSuite = JubJubSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::JUBJUB, hash::SHA512, h2c::TAI);
    type Affine = ark_ed_on_bls12_381::EdwardsAffine;
    type Transcript = utils::HashTranscript;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "2671563590660729217877867502637159080924340550540298316336804174287037983535"
        );
        const Y: BaseField = MontFp!(
            "27990482544029132573047185251102012550987670910599975985529822463373166358391"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "20522558845338057984236756677352955204440764593388078806320820759828434217414"
        );
        const Y: BaseField = MontFp!(
            "30640182283898004439951532793265155461990384517852369791254931716384123542036"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField =
            MontFp!("38956341538508863744993405884988306267554601876436576952130150310707616181394");
        const Y: BaseField = MontFp!(
            "20837124983713908503950353873416686644548370407048794182669789602967149453355"
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
        const SUITE_NAME: &str = "jubjub_sha-512_tai";
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
}
