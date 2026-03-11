//! # ECVRF P256 SHA-256 TAI suite
//!
//! Configuration inspired by RFC-9381 (ECVRF-P256-SHA256-TAI):
//!
//! *  `suite_string` = `b"Secp256r1_SHA-256_TAI"`.
//!
//! *  The EC group G is the NIST P-256 elliptic curve, with the finite
//!    field and curve parameters as specified in Section 3.2.1.3 of
//!    [SP-800-186](https://csrc.nist.gov/pubs/sp/800/186/final) and
//!    Section 2.6 of [RFC-5114](https://www.rfc-editor.org/rfc/rfc5114).
//!    For this group, `fLen = qLen = 32` and `cofactor = 1`.
//!
//! *  `cLen` = 16.
//!
//! *  The key pair generation primitive is specified in Section 3.2.1 of
//!    SECG1 (q, B, SK, and Y in this document correspond to n, G, d,
//!    and Q in Section 3.2.1 of SECG1).  In this ciphersuite, the
//!    secret scalar x is equal to the secret key SK.
//!
//! *  Nonce generation is inspired by Section 5.4.2.1 of RFC-9381,
//!    adapted to use the suite's pluggable transcript.
//!
//! *  The int_to_string function is the I2OSP function specified in
//!    Section 4.1 of RFC-8017.  (This is big-endian representation.)
//!
//! *  The string_to_int function is the OS2IP function specified in
//!    Section 4.2 of RFC-8017.  (This is big-endian representation.)
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string according to the encoding specified in Section 2.3.3 of
//!    SECG1 with point compression on.  This implies that
//!    ptLen = fLen + 1 = 33.
//!
//! *  The string_to_point function converts an octet string to a point
//!    on E according to the encoding specified in Section 2.3.4 of
//!    SECG1.  This function MUST output "INVALID" if the octet string
//!    does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-256 as specified in RFC-6234, with
//!    hLen = 32.
//!
//! *  The ECVRF_encode_to_curve function uses Try-And-Increment, inspired
//!    by Section 5.4.1.1 of RFC-9381.

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Secp256r1Sha256Tai;

type ThisSuite = Secp256r1Sha256Tai;

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::SECP256R1, hash::SHA256, h2c::TAI);
    type Affine = ark_secp256r1::Affine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "19332285192927557680405700411206968974672873994469106027400248693763961695896"
        );
        const Y: BaseField = MontFp!(
            "78970180227973274407170824355915625461235681567349560981029425998910017832833"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::SuiteExt;

    impl SuiteExt for ThisSuite {
        const SUITE_NAME: &str = "secp256r1_sha-256_tai";
    }

    ietf_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);
}
