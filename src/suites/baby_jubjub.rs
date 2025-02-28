//! `ECVRF Baby-JubJub SHA-512 Elligator2` suite.
//!
//! Configuration:
//!
//! * `suite_string` = b"BabyJubJub_SHA-512_TAI".
//!
//! - The EC group <G> TODO.
//!
//! - The prime subgroup generator G in <G> is defined as follows:
//!   - G.x = TODO
//!   - G.y = TODO
//!
//! * `cLen` = 32.
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
//! * The point_to_string function converts a point in <G> to an octet
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
//!   with `h2c_suite_ID_string` = `"BabyJubJub:SHA-512_TAI_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabyJubJubSha512Ell2;

type ThisSuite = BabyJubJubSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"BabyJubJub_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 32;

    type Affine = ark_ed_on_bn254::EdwardsAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("5376532244618542109661131277363905439212836542753147027865558121391900167688");
        const Y: BaseField = MontFp!(
            "16889430036387258317292938764306353102387558736297768366398133205840396603585"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bn254::Bn254;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "14244296864466975185765191286346905764168103931054421124968917222697157902984"
        );
        const Y: BaseField =
            MontFp!("1338211929751438779479461215010533627729802740411746374590569050486264053400");
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "11609282441801662122102628199525114984581229682260025690337510332048945634398"
        );
        const Y: BaseField =
            MontFp!("8183188953682575835393390021093178644584738701798006422551483781204555462701");
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

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BN254_PCS_SRS_FILE;

        fn context() -> &'static RingContext {
            use std::sync::OnceLock;
            static RING_CTX: OnceLock<RingContext> = OnceLock::new();
            RING_CTX.get_or_init(Self::load_context)
        }
    }
}
