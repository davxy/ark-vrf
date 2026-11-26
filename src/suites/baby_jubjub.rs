//! # ECVRF Baby-JubJub SHA-512 TAI suite
//!
//! With the shared rules of [`crate::suites`].
//!
//! - `SUITE_ID` = `b"BabyJubJub-SHA512-TAI-v1"`.
//! - `G` is the prime-order subgroup of the Baby-JubJub curve of
//!   <https://github.com/barryWhiteHat/baby_jubjub>. `fLen` = `qLen` = 32 and
//!   `cofactor` = 8. The generator is:
//!   - `G.x` = 19698561148652590122159747500897617769866003486955115824547446575314762165298
//!   - `G.y` = 19298250018296453272277890825869354524455968081175474282777126169995084727839
//! - Hash: SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)),
//!   `hLen` = 64.
//! - `ECVRF_encode_to_curve`: try-and-increment, after RFC 9381 section
//!   5.4.1.1.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Baby-JubJub, SHA-512, try-and-increment hash-to-curve.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabyJubJubSha512Tai;

type ThisSuite = BabyJubJubSha512Tai;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"BabyJubJub-SHA512-TAI-v1";
    type Affine = ark_ed_on_bn254::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "15549380791300914366206471199568039679131690710803662429646809536753521087193"
        );
        const Y: BaseField = MontFp!(
            "15218614024055502695611547593111691164731001864276292210438920202280814188379"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bn254::Bn254;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("6402374321243162085389111671722843560682527921646684137786768606010797479351");
        const Y: BaseField =
            MontFp!("9735581299071570006712034490635195155689931359428941496570758703259384062170");
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "11167490195257431015694161063225325511805242064780376648595733691987293447528"
        );
        const Y: BaseField = MontFp!(
            "18403369502642103292159933062507105566469227524991433735553439433605496057425"
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
        const SUITE_NAME: &str = "baby-jubjub_sha-512_tai";
    }

    suite_tests!(ThisSuite);
    tiny_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
    thin_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BN254_PCS_SRS_FILE;

        fn ring_setup() -> &'static RingSetup {
            use std::sync::OnceLock;
            static RING_SETUP: OnceLock<RingSetup> = OnceLock::new();
            RING_SETUP.get_or_init(Self::load_ring_setup)
        }
    }
}
