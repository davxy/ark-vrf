//! # ECVRF Bandersnatch SHAKE128 Elligator2 suite
//!
//! Same curve, generator and encodings as [`super::bandersnatch`], with
//! SHAKE128 in place of SHA-512 in the two places that hash:
//!
//! * `SUITE_ID` = b"Bandersnatch-SHAKE128-ELL2-v1"
//!
//! * `cLen` = 16 (128-bit security level).
//!
//! * The Fiat-Shamir transcript is a
//!   [`Shake128Transcript`](crate::utils::Shake128Transcript), SHAKE128 in
//!   XOF mode, instead of the SHA-512 based one.
//!
//! * The `ECVRF_encode_to_curve` function uses the *Elligator2* method of
//!   RFC 9380 section 6.8.2 with `expand_message_xof` over SHAKE128
//!   (section 5.3.2) in place of `expand_message_xmd` over SHA-512, see
//!   [`crate::utils::hash_to_curve_ell2_xof`]. The domain separation tag has
//!   the same `DST = SUITE_ID || DomSep::HashToCurve` form. The blinding
//!   base, the accumulator base and the padding point are this suite's own.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Bandersnatch in Twisted Edwards form, SHAKE128, Elligator2 hash-to-curve.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchShake128Ell2;

type ThisSuite = BandersnatchShake128Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch-SHAKE128-ELL2-v1";
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::Shake128Transcript;

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        utils::hash_to_curve_ell2_xof::<Self, sha3::Shake128>(data)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("6153734995852631824944342602386415873379775188383988340041079006556670120775");
        const Y: BaseField = MontFp!(
            "27204351599954061630605768787803524395123895650061061132592995395630473050754"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "27631238720955528589004064829276283990465032040945349648037876197995278250917"
        );
        const Y: BaseField = MontFp!(
            "37605358688136619817560700742505556266961225274493904038881144193539047100140"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField =
            MontFp!("1834402953989431481748983728202937234471322740714585873803966488035889514523");
        const Y: BaseField = MontFp!(
            "52100941849053769665273763352270294131006971127418863694682093199651869272752"
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

    suite_tests!(ThisSuite);
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
