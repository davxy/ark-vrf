//! # ECVRF Secp256r1 SHA-256 TAI suite
//!
//! Configuration inspired by RFC-9381 (ECVRF-P256-SHA256-TAI). The encodings
//! and the key derivation are the ones shared by every suite of this crate,
//! not the SEC1 and big-endian ones of RFC-9381:
//!
//! *  `SUITE_ID` = `b"Secp256r1-SHA256-TAI-v1"`.
//!
//! *  The EC group G is the NIST P-256 elliptic curve, with the finite
//!    field and curve parameters as specified in Section 3.2.1.3 of
//!    [SP-800-186](https://csrc.nist.gov/pubs/sp/800/186/final) and
//!    Section 2.6 of [RFC-5114](https://www.rfc-editor.org/rfc/rfc5114).
//!    For this group, `fLen = qLen = 32` and `cofactor = 1`.
//!
//! *  `cLen` = 16 (128-bit security level).
//!
//! *  The key pair generation primitive is _PK = sk * G_, with G the group
//!    generator. In this ciphersuite, the secret scalar x is equal to the
//!    secret key scalar sk. A secret derived from a seed follows
//!    [`Secret::from_seed`].
//!
//! *  Nonce generation is deterministic through the suite transcript, see
//!    [`Suite::nonce`]. It is inspired by Section 5.4.2.2 of RFC-9381, not
//!    by the RFC-6979 method of Section 5.4.2.1.
//!
//! *  The int_to_string function encodes into the 32 bytes little-endian
//!    representation. The challenge `c` is encoded on its low `cLen` bytes.
//!
//! *  The string_to_int function decodes from the 32 bytes little-endian
//!    representation.
//!
//! *  The point_to_string function converts a point in G to an octet
//!    string using compressed form: the x coordinate encoded with
//!    int_to_string, followed by one flag octet. The flag is `0x00` when the
//!    integer y is at most `(p - 1) / 2` and `0x80` otherwise; the identity
//!    has its own flag `0x40` and is never a valid public key or output.
//!    This implies that ptLen = fLen + 1 = 33. This is not the SEC1 encoding
//!    of RFC-9381, which uses a big-endian x after a leading `0x02` or `0x03`.
//!
//! *  The string_to_point function tries to decompress the point encoded
//!    according to `point_to_string` procedure. This function MUST output
//!    "INVALID" if the octet string does not decode to a point on G.
//!
//! *  The hash function Hash is SHA-256 as specified in
//!    [RFC6234](https://www.rfc-editor.org/rfc/rfc6234), with hLen = 32.
//!
//! *  The ECVRF_encode_to_curve function uses Try-And-Increment, inspired
//!    by Section 5.4.1.1 of RFC-9381, see [`crate::utils::hash_to_curve_tai`].

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Secp256r1 (NIST P-256), SHA-256, try-and-increment hash-to-curve.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Secp256r1Sha256Tai;

type ThisSuite = Secp256r1Sha256Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Secp256r1-SHA256-TAI-v1";
    type Affine = ark_secp256r1::Affine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("100063053743935619201936855760019111820847755970243670581468062459849338000");
        const Y: BaseField = MontFp!(
            "113675507039234898358330549589155441528265243038226986303017485279501143145422"
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

    suite_tests!(ThisSuite);
    tiny_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);
}
