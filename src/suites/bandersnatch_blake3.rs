//! # ECVRF Bandersnatch BLAKE3 Elligator2 suite
//!
//! Same curve and hash-to-curve as [`super::bandersnatch`] but using a
//! [`Blake3Transcript`](crate::utils::Blake3Transcript) for the Fiat-Shamir
//! transform instead of the default SHA-512 based one.
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_BLAKE3_ELL2"
//!
//! - The EC group, generator, encoding conventions, and Elligator2
//!   hash-to-curve are identical to the SHA-512 variant.
//!
//! * `cLen` = 16 (128-bit security).
//!
//! * The Fiat-Shamir transcript uses BLAKE3 in XOF mode.

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchBlake3Ell2;

type ThisSuite = BandersnatchBlake3Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::BANDERSNATCH, hash::BLAKE3, h2c::ELL2);
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::Blake3Transcript;

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        let h2c_suite_id = b"Bandersnatch_XOF:BLAKE3_ELL2_RO_";
        utils::hash_to_curve_ell2_xof::<Self, blake3::Hasher>(data, h2c_suite_id)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "12703136799781416300084182741725379308061550338376793251000109922182802194115"
        );
        const Y: BaseField = MontFp!(
            "22249971876460514874188991348979386779001547306226358202468447381416829661519"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("3004050047863732153057662410765511549614878442475148073423780940555234479512");
        const Y: BaseField = MontFp!(
            "25378325936133378578597792826305229016560882689085284942194526817274714954341"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField =
            MontFp!("4876829915585758941207310275748479689328611676355330526286026025679021077058");
        const Y: BaseField = MontFp!(
            "43559401107451028848214889050975288046130501743109650114692550691404100841274"
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
        const SUITE_NAME: &str = "bandersnatch_blake3_ell2";
    }

    tiny_suite_tests!(ThisSuite);
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
