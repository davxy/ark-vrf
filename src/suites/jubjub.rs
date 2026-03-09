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
    type Affine = ark_ed_on_bls12_381::EdwardsAffine;
    type Transcript = utils::HashTranscript;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "22743556398734409900025626316785672841596839835434714031697780871242821707576"
        );
        const Y: BaseField = MontFp!(
            "14276288985173455751342965637812080846702058796460743601649560838014102603234"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "30234636372141880557893261619713702757614395705825588651266060373664494747679"
        );
        const Y: BaseField = MontFp!(
            "41672410851744404078620008392382829953514074659836219477025365589023597063476"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField =
            MontFp!("3876255365802395935256878635595392441546203305340268390083419334501068031804");
        const Y: BaseField =
            MontFp!("4341287263698300412009187588022078643819259512839234189232943183631959903998");
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {}

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
