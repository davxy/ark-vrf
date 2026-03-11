//! # ECVRF Bandersnatch SHAKE128 Elligator2 suite
//!
//! Same curve and hash-to-curve as [`super::bandersnatch`] but using a
//! [`Shake128Transcript`](crate::utils::Shake128Transcript) for the Fiat-Shamir
//! transform instead of the default SHA-512 based one.
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_SHAKE128_ELL2"
//!
//! - The EC group, generator, encoding conventions, and Elligator2
//!   hash-to-curve are identical to the SHA-512 variant.
//!
//! * `cLen` = 16 (128-bit security).
//!
//! * The Fiat-Shamir transcript uses SHAKE128 in XOF mode.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchShake128Ell2;

type ThisSuite = BandersnatchShake128Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch_SHAKE128_ELL2";
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::Shake128Transcript;

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        let h2c_suite_id = b"Bandersnatch_XOF:SHAKE128_ELL2_RO_";
        utils::hash_to_curve_ell2_xof::<Self, sha3::Shake128>(data, h2c_suite_id)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "44187783804308655615893812990316292961554469480416662436801239487565822353178"
        );
        const Y: BaseField = MontFp!(
            "35971809727456608433294066984788155999592825372652107534495786488037270016538"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "20639374388924227724771638774449398719556116172205860866799883237248913745842"
        );
        const Y: BaseField = MontFp!(
            "38136419370012340917734197581369752597848441414667300682263855321096366682161"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "38904451821106192188322921836918159879943183484139281754639349115574962210181"
        );
        const Y: BaseField = MontFp!(
            "10958085554412341870030204421258475929791168123815622987225019222099864665145"
        );
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

    #[test]
    fn elligator2_hash_to_curve() {
        use crate::testing::CheckPoint;
        let raw = crate::testing::random_vec(42, None);
        assert!(
            ThisSuite::data_to_point(&raw)
                .map(|p| p.check(true).ok())
                .is_some()
        );
    }
}
