//! # ECVRF Bandersnatch SHA-512 Elligator2 suite, version 1
//!
//! The [`super::bandersnatch`] suite of ark-vrf 0.5, with the same outputs.
//! It differs from the current suite in two places:
//!
//! * `SUITE_ID` = b"Bandersnatch-SHA512-ELL2-v1".
//!
//! * The zero prefix `Z_pad` of `expand_message_xmd` has 48 bytes, the
//!   expanded field element length of the arkworks 0.6 `DefaultFieldHasher`,
//!   and not the 128 byte SHA-512 input block that RFC 9380 section 5.3.1
//!   requires.
//!
//! The blinding base, the accumulator base and the padding point are this
//! suite's own.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Bandersnatch in Twisted Edwards form, SHA-512, Elligator2 hash-to-curve,
/// version 1.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Ell2;

type ThisSuite = BandersnatchSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch-SHA512-ELL2-v1";
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        utils::hash_to_curve::hash_to_curve_ell2_xmd_arkworks_compat::<Self, sha2::Sha512>(data)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "23335687741101763108036518445642207119627658113885888016488710494487028845889"
        );
        const Y: BaseField =
            MontFp!("5552214580375038693022409684979828600325210968745774080859660443337357929963");
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "14056632001415368875257708737821299882600475929746323097150942355715730684350"
        );
        const Y: BaseField = MontFp!(
            "10322661992765989500407719465917595459409463902187386706652408883505670839210"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "26913883415342152801331916189968962157924271221160514298872262294143390094043"
        );
        const Y: BaseField = MontFp!(
            "30874728313203001508631936119690348239461579770372782660098261717479009115354"
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
        const SUITE_NAME: &str = "bandersnatch_v1_sha-512_ell2";
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
}
