//! # ECVRF Ed25519 SHA-512 TAI suite
//!
//! After RFC 9381 (ECVRF-EDWARDS25519-SHA512-TAI), with the shared rules of
//! [`crate::suites`].
//!
//! - `SUITE_ID` = `b"Ed25519-SHA512-TAI-v1"`.
//! - `G` is the prime-order subgroup of edwards25519, with the parameters of
//!   [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) section 5.1, Table 1.
//!   `fLen` = `qLen` = 32 and `cofactor` = 8.
//! - Hash: SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)),
//!   `hLen` = 64.
//! - `ECVRF_encode_to_curve`: try-and-increment (see
//!   [`crate::utils::hash_to_curve_tai`]).
//!
//! Differences from RFC 8032: a seed does not get the SHA-512 expansion and the
//! clamping of section 5.1.5. The point encoding marks `x > (p - 1) / 2`, where
//! RFC 8032 section 5.1.2 stores the parity of `x`, so the encodings differ for
//! about half of the points.

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
