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
    const SUITE_ID: &'static [u8] = b"Bandersnatch-SHAKE128-ELL2";
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
            "34292064296724983548061097563749145869435166350203523102839250739673770750310"
        );
        const Y: BaseField = MontFp!(
            "30198598861948352181811816706184987796862133355584048473214770353589716455342"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("33666478644776764439575141213418496933841503878180789184594816322665311620920");
        const Y: BaseField = MontFp!(
            "16966219539779057437306348136898285709366104659346235043386946054418989417527"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "16621586053709220806397644410005679764552702781676936393180204527559724729483"
        );
        const Y: BaseField = MontFp!(
            "23869037814230183677291705774518599477372176724517258045838240987113781341978"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {
        const SUITE_NAME: &str = "bandersnatch_shake128_ell2";
    }

    tiny_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BLS12_381_PCS_SRS_FILE;

        fn ring_setup() -> &'static RingSetup {
            use std::sync::OnceLock;
            static RING_SETUP: OnceLock<RingSetup> = OnceLock::new();
            RING_SETUP.get_or_init(Self::load_ring_setup)
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
