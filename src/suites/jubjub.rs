//! # ECVRF JubJub SHA-512 TAI suite
//!
//! With the shared rules of [`crate::suites`].
//!
//! - `SUITE_ID` = `b"JubJub-SHA512-TAI-v1"`.
//! - `G` is the prime-order subgroup of the JubJub curve of
//!   <https://github.com/zkcrypto/jubjub>. `fLen` = `qLen` = 32 and
//!   `cofactor` = 8. The generator is:
//!   - `G.x` = 8076246640662884909881801758704306714034609987455869804520522091855516602923
//!   - `G.y` = 13262374693698910701929044844600465831413122818447359594527400194675274060458
//! - Hash: SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)),
//!   `hLen` = 64.
//! - `ECVRF_encode_to_curve`: try-and-increment, after RFC 9381 section
//!   5.4.1.1.
//!
//! The zkcrypto `jubjub` crate stores the parity of `x` in the point encoding,
//! so its encodings differ from these.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// JubJub, SHA-512, try-and-increment hash-to-curve.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct JubJubSha512Tai;

type ThisSuite = JubJubSha512Tai;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"JubJub-SHA512-TAI-v1";
    type Affine = ark_ed_on_bls12_381::EdwardsAffine;
    type Transcript = utils::HashTranscript;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "38206460563694846719174258613922853630278999941532690543235578292520143148532"
        );
        const Y: BaseField = MontFp!(
            "34254498978062207918041301829525626783549813531091321004550549786528984401675"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "48142684311216766702182564801462043940571084233680216669499475549492432046964"
        );
        const Y: BaseField = MontFp!(
            "34380560660182334518990118617091967209302636551264477863958902286043397647879"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "17348704025397475127937572481155408456556065464328870407269802701696798733683"
        );
        const Y: BaseField = MontFp!(
            "24318278422173803457621119807961883607097742387673491974779969503617097905596"
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
        const SUITE_NAME: &str = "jubjub_sha-512_tai";
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
