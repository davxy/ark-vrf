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

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchBlake3Ell2;

type ThisSuite = BandersnatchBlake3Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch_BLAKE3_ELL2";
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::Blake3Transcript;

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        let h2c_suite_id = b"Bandersnatch_XOF:BLAKE3_ELL2_RO_";
        utils::hash_to_curve_ell2_xof::<Self, blake3::Hasher>(data, h2c_suite_id)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("4694736462969538177633076268939481600284529045693413086948076212480794677199");
        const Y: BaseField = MontFp!(
            "44714752015458287727737029715031577921793209541326637377209347957465163260255"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "32763920831565874760711468536717808838982655760789027965978335169882468593426"
        );
        const Y: BaseField = MontFp!(
            "51673700554633953592104332292009263870711506270325837054595685315050398808993"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "51631191573608788827781948097192921797975449885387023060061092150360505937460"
        );
        const Y: BaseField = MontFp!(
            "35434892137228356617010304027130304746797305548693889536955019689347861726399"
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
