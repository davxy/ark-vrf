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

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchShake128Ell2;

type ThisSuite = BandersnatchShake128Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::BANDERSNATCH, hash::SHAKE128, h2c::ELL2);
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
            "49711633503578088461102475482758123714990448359295893023691701223600041108880"
        );
        const Y: BaseField = MontFp!(
            "21734535912282350924958086363828906945752028855014763377074407104422660758024"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("1105742357637387425254396768873203554198272572277105936723136162395083529964");
        const Y: BaseField = MontFp!(
            "24692986946683088850660234448507437420531514109850582636728489358857902590633"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "35722209352759705891151029231528077394352533506856562381258237384901639230791"
        );
        const Y: BaseField = MontFp!(
            "45896426634892825397032453843712070506002279593299307059809550559743613966408"
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
