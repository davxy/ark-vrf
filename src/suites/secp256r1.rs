//! # ECVRF Secp256r1 SHA-256 TAI suite
//!
//! After RFC 9381 (ECVRF-P256-SHA256-TAI), with the shared rules of
//! [`crate::suites`].
//!
//! - `SUITE_ID` = `b"Secp256r1-SHA256-TAI-v1"`.
//! - `G` is the NIST P-256 curve, with the parameters of
//!   [SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final) section 3.2.1.3
//!   and [RFC 5114](https://www.rfc-editor.org/rfc/rfc5114) section 2.6.
//!   `fLen` = `qLen` = 32 and `cofactor` = 1.
//! - Hash: SHA-256 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)),
//!   `hLen` = 32.
//! - `ECVRF_encode_to_curve`: try-and-increment (see
//!   [`crate::utils::hash_to_curve_tai`]).
//!
//! Differences from RFC 9381: the encodings are little-endian and the point
//! encoding is not SEC1 (a leading `0x02` or `0x03` and a big-endian `x`). The
//! nonce does not use the RFC 6979 method of section 5.4.2.1.

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
