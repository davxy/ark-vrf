//! # ECVRF Ed25519 SHA-512 TAI suite
//!
//! Configuration inspired by RFC-9381 (ECVRF-EDWARDS25519-SHA512-TAI). The
//! encodings and the key derivation are the ones shared by every suite of
//! this crate; they differ from RFC-8032 where this doc says so:
//!
//! *  `SUITE_ID` = `b"Ed25519-SHA512-TAI-v1"`.
//!
//! *  The EC group G is the prime order subgroup of the edwards25519
//!    elliptic curve, with the finite field and curve parameters as defined
//!    in Table 1 in Section 5.1 of
//!    [RFC8032](https://www.rfc-editor.org/rfc/rfc8032).
//!    For this group, fLen = qLen = 32 and cofactor = 8.
//!
//! *  `cLen` = 16 (128-bit security level).
//!
//! *  The key pair generation primitive is _PK = sk * G_, with G the group
//!    generator. In this ciphersuite, the secret scalar x is equal to the
//!    secret key scalar sk. A secret derived from a seed follows
//!    [`Secret::from_seed`]: no SHA-512 expansion of the seed and no
//!    clamping, unlike Section 5.1.5 of RFC-8032.
//!
//! *  Nonce generation is deterministic through the suite transcript, see
//!    [`Suite::nonce`]. It is inspired by Section 5.4.2.2 of RFC-9381.
//!
//! *  The int_to_string function encodes into the 32 bytes little-endian
//!    representation, as the first paragraph of Section 5.1.2 of RFC-8032.
//!    The challenge `c` is encoded on its low `cLen` bytes.
//!
//! *  The string_to_int function decodes from the 32 bytes little-endian
//!    representation.
//!
//! *  The point_to_string function converts a point in G to an octet
//!    string using compressed form. The y coordinate is encoded using
//!    int_to_string function and the most significant bit of the last
//!    octet is set when the integer x is greater than `(p - 1) / 2`.
//!    Section 5.1.2 of RFC-8032 stores the least significant bit of x in
//!    that position instead, so the two encodings differ for about half of
//!    the points. This implies that ptLen = fLen = 32.
//!
//! *  The string_to_point function tries to decompress the point encoded
//!    according to `point_to_string` procedure. This function MUST output
//!    "INVALID" if the octet string does not decode to a point on G.
//!
//! *  The hash function Hash is SHA-512 as specified in
//!    [RFC6234](https://www.rfc-editor.org/rfc/rfc6234), with hLen = 64.
//!
//! *  The ECVRF_encode_to_curve function uses Try-And-Increment, inspired
//!    by Section 5.4.1.1 of RFC-9381, see [`crate::utils::hash_to_curve_tai`].

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Ed25519_SHA-512_TAI Suite.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ed25519Sha512Tai;

type ThisSuite = Ed25519Sha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Ed25519-SHA512-TAI-v1";
    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "45003173884697328536089278691112838614164406922820087464913813433380838325453"
        );
        const Y: BaseField = MontFp!(
            "31256014272390301975555524011230972931324093235775711248505761870355310252869"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {
        const SUITE_NAME: &str = "ed25519_sha-512_tai";
    }

    suite_tests!(ThisSuite);
    tiny_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);
}
