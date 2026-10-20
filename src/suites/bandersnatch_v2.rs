//! # ECVRF Bandersnatch SHA-512 Elligator2 suite, version 2
//!
//! It differs from version 1, [`super::bandersnatch`], in two places:
//!
//! * `SUITE_ID` = b"Bandersnatch-SHA512-ELL2-v2".
//!
//! * The zero prefix `Z_pad` of `expand_message_xmd` has 128 bytes, the
//!   SHA-512 input block that RFC 9380 section 5.3.1 requires, and not the
//!   48 bytes of the arkworks 0.6 `DefaultFieldHasher`.
//!
//! The blinding base, the accumulator base and the padding point are this
//! suite's own. The
//! [Bandersnatch VRF specification](https://github.com/davxy/bandersnatch-vrf-spec)
//! currently recommends version 1.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Bandersnatch in Twisted Edwards form, SHA-512, Elligator2 hash-to-curve,
/// version 2.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Ell2;

type ThisSuite = BandersnatchSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch-SHA512-ELL2-v2";
    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        utils::hash_to_curve_ell2_xmd::<Self, sha2::Sha512>(data)
    }
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "22118296430398992055659154342014487674511290404553062345415468198994042557513"
        );
        const Y: BaseField = MontFp!(
            "18459022064371835405469327450010492648577157228683351878003831466280791690623"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "13464469348211009478996801625416047694368983200892816868679829969586642297960"
        );
        const Y: BaseField =
            MontFp!("3798694867683671293969902550342975803355534254442652542336263418633380224327");
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "18789570585008552774270602428553056801045807996334418548416712705681035018569"
        );
        const Y: BaseField = MontFp!(
            "14678106766635305884560840136502131745233404248640991555472450068125753994317"
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
        const SUITE_NAME: &str = "bandersnatch_v2_sha-512_ell2";
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
