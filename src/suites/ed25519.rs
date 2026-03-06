//! # ECVRF Ed25519 SHA-512 TAI suite
//!
//! Configuration (RFC-9381 with some compromises):
//!
//! *  suite_string = b"ed25519-sha512-tai"
//!    We slightly deviate from the suite described in RFC-9381, thus
//!    we prefer to not use suite id `[0x03]`.
//!
//! *  The EC group G is the edwards25519 elliptic curve, with the finite
//!    field and curve parameters as defined in Table 1 in Section 5.1 of
//!    `[RFC8032]`.  For this group, fLen = qLen = 32 and cofactor = 8.
//!
//! *  cLen = 16.
//!
//! *  The secret key and generation of the secret scalar and the public
//!    key are specified in Section 5.1.5 of `[RFC8032]`.
//!
//! *  The ECVRF_nonce_generation function is as specified in
//!    Section 5.4.2.2.
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
//!    `[RFC8032]`.  This implies that ptLen = fLen = 32.  (Note that
//!    certain software implementations do not introduce a separate
//!    elliptic curve point type and instead directly treat the EC point
//!    as an octet string per the above encoding.  When using such an
//!    implementation, the point_to_string function can be treated as the
//!    identity function.)
//!
//! *  The string_to_point function converts an octet string to a point
//!    on E according to the encoding specified in Section 5.1.3 of
//!    `[RFC8032]`.  This function MUST output "INVALID" if the octet
//!    string does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-512 as specified in `[RFC6234]`, with
//!    `hLen = 64`.
//!
//! *  The ECVRF_encode_to_curve function is as specified in
//!    Section 5.4.1.1, with `interpret_hash_value_as_a_point(s) =
//!    string_to_point(s[0]...s[31])`.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Ed25519_SHA-512_TAI Suite.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ed25519Sha512Tai;

type ThisSuite = Ed25519Sha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Ed25519_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed25519::EdwardsAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;

    fn data_to_point(data: &[u8]) -> Option<crate::AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }

    fn nonce(sk: &crate::ScalarField<Self>, pts: &[&crate::AffinePoint<Self>], ad: &[u8]) -> crate::ScalarField<Self> {
        utils::nonce_rfc_8032::<Self>(sk, pts, ad)
    }

    fn challenge(pts: &[&crate::AffinePoint<Self>], ad: &[u8]) -> crate::ScalarField<Self> {
        utils::challenge_rfc_9381::<Self>(pts, ad)
    }

    fn point_to_hash(pt: &crate::AffinePoint<Self>) -> crate::HashOutput<Self> {
        utils::point_to_hash_rfc_9381::<Self>(pt, false)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "34964248752573453964991712365053444197578929845336037029678529379743871798804"
        );
        const Y: BaseField = MontFp!(
            "55999826975077435406782459267347332622048692966399536187484076777078341641749"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {}

    codec_suite_tests!(ThisSuite);
    ietf_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);
}
