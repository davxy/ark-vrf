//! ECVRF Baby-JubJub SHA-512 TAI suite
//!
//! Configuration:
//!
//! * `SUITE_ID` = b"BabyJubJub-SHA512-TAI".
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

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabyJubJubSha512Tai;

type ThisSuite = BabyJubJubSha512Tai;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"BabyJubJub-SHA512-TAI";
    type Affine = ark_ed_on_bn254::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "15797289012139890952918652741983061499993108868002576830851728385607852258421"
        );
        const Y: BaseField = MontFp!(
            "17743238679668623128365684338219902634658870082338213231202641821728201928604"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bn254::Bn254;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "21433810013380207923117265600927837050017035925963604061655421603544881837522"
        );
        const Y: BaseField =
            MontFp!("6775681885644986793719018988119744802486174723011050942341663377165653894592");
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "16578944628535772021649872858836608926257290522186066354674854052388117281285"
        );
        const Y: BaseField =
            MontFp!("8245891045969063948555066877845954229931266423611340592496179617443193979568");
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

    tiny_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BN254_PCS_SRS_FILE;

        fn ring_setup() -> &'static RingSetup {
            use std::sync::OnceLock;
            static RING_SETUP: OnceLock<RingSetup> = OnceLock::new();
            RING_SETUP.get_or_init(Self::load_ring_setup)
        }
    }
}
