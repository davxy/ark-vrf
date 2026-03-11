//! # ECVRF Ed25519 SHA-512 TAI suite
//!
//! Configuration inspired by RFC-9381 (ECVRF-EDWARDS25519-SHA512-TAI):
//!
//! *  `suite_string` = `b"Ed25519_SHA-512_TAI"`.
//!
//! *  The EC group G is the edwards25519 elliptic curve, with the finite
//!    field and curve parameters as defined in Table 1 in Section 5.1 of
//!    `[RFC8032]`.  For this group, fLen = qLen = 32 and cofactor = 8.
//!
//! *  `cLen` = 16.
//!
//! *  The secret key and generation of the secret scalar and the public
//!    key are specified in Section 5.1.5 of `[RFC8032]`.
//!
//! *  Nonce generation is inspired by Section 5.4.2.2 of RFC-9381,
//!    adapted to use the suite's pluggable transcript.
//!
//! *  The int_to_string function is implemented as specified in the
//!    first paragraph of Section 5.1.2 of `[RFC8032]`.  (This is little-
//!    endian representation.)
//!
//! *  The string_to_int function interprets the string as an integer in
//!    little-endian representation.
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string according to the encoding specified in Section 5.1.2 of
//!    `[RFC8032]`.  This implies that ptLen = fLen = 32.
//!
//! *  The string_to_point function converts an octet string to a point
//!    on E according to the encoding specified in Section 5.1.3 of
//!    `[RFC8032]`.  This function MUST output "INVALID" if the octet
//!    string does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-512 as specified in `[RFC6234]`, with
//!    `hLen = 64`.
//!
//! *  The ECVRF_encode_to_curve function uses Try-And-Increment, inspired
//!    by Section 5.4.1.1 of RFC-9381.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Ed25519_SHA-512_TAI Suite.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ed25519Sha512Tai;

type ThisSuite = Ed25519Sha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Ed25519_SHA-512_TAI";
    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "36295583474313307408628688145858999985455683979892549111805148820123910068316"
        );
        const Y: BaseField = MontFp!(
            "26572103949519065985696377529624549616752501986257345746421638266910471133905"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {}

    ietf_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);
}
