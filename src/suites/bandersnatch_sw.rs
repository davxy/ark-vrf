//! # ECVRF Bandersnatch-SW SHA-512 TAI suite
//!
//! With the shared rules of [`crate::suites`].
//!
//! - `SUITE_ID` = `b"Bandersnatch-SW-SHA512-TAI-v1"`.
//! - `G` is the prime-order subgroup of the Bandersnatch curve in short
//!   Weierstrass form, with the parameters of
//!   [MSZ21](https://eprint.iacr.org/2021/1152). `fLen` = `qLen` = 32 and
//!   `cofactor` = 4. The generator is:
//!   - `G.x` = 30900340493481298850216505686589334086208278925799850409469406976849338430199
//!   - `G.y` = 12663882780877899054958035777720958383845500985908634476792678820121468453298
//! - Hash: SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)),
//!   `hLen` = 64.
//! - `ECVRF_encode_to_curve`: try-and-increment, after RFC 9381 section
//!   5.4.1.1.

use crate::{pedersen::PedersenSuite, utils::te_sw_map::*, *};
use ark_ff::MontFp;

/// Bandersnatch in Short Weierstrass form, SHA-512, try-and-increment hash-to-curve.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Tai;

type ThisSuite = BandersnatchSha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Bandersnatch-SW-SHA512-TAI-v1";
    type Affine = ark_ed_on_bls12_381_bandersnatch::SWAffine;
    type Transcript = utils::HashTranscript<sha2::Sha512>;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "28115362618644671219696075022370511395136332234538034358311199318506963235315"
        );
        const Y: BaseField =
            MontFp!("3900851469868158154936962463930962496000252801946757953905982128670530185313");
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "13189182432637108534251278524663360416811744717379968387043749958796254980045"
        );
        const Y: BaseField = MontFp!(
            "14483286006782706188671626508232161325054303360192563232232823772738911894793"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "20496180070424734470560955314776462366297546779079302509428101119888111900885"
        );
        const Y: BaseField =
            MontFp!("8839106592405352067483360946162273985142890146060814748321063063028225641813");
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

// sage: q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
// sage: Fq = GF(q)
// sage: MONT_A = 29978822694968839326280996386011761570173833766074948509196803838190355340952
// sage: MONT_B = 25465760566081946422412445027709227188579564747101592991722834452325077642517
// sage: MONT_A/Fq(3) = 9992940898322946442093665462003920523391277922024982836398934612730118446984
// sage: Fq(1)/MONT_B = 41180284393978236561320365279764246793818536543197771097409483252169927600582
impl MapConfig for ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig {
    const MONT_A_OVER_THREE: ark_ed_on_bls12_381_bandersnatch::Fq =
        MontFp!("9992940898322946442093665462003920523391277922024982836398934612730118446984");
    const MONT_B_INV: ark_ed_on_bls12_381_bandersnatch::Fq =
        MontFp!("41180284393978236561320365279764246793818536543197771097409483252169927600582");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{testing, tiny_suite_tests};
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, SWAffine};

    impl crate::testing::SuiteExt for ThisSuite {
        const SUITE_NAME: &str = "bandersnatch_sw_sha-512_tai";
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
    fn sw_to_te_roundtrip() {
        let roundtrip = |org_point| {
            let te_point = sw_to_te::<BandersnatchConfig>(&org_point).unwrap();
            assert!(te_point.is_on_curve());
            let sw_point = te_to_sw::<BandersnatchConfig>(&te_point).unwrap();
            assert!(sw_point.is_on_curve());
            assert_eq!(org_point, sw_point);
        };
        roundtrip(testing::random_val::<SWAffine>(None));
        roundtrip(AffinePoint::generator());
    }

    #[test]
    fn identity_point_rejected() {
        use ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;

        // SW identity -> TE must fail
        let sw_identity = SWAffine::zero();
        assert!(sw_to_te::<BandersnatchConfig>(&sw_identity).is_none());
        assert!(<SWAffine as TEMapping<BandersnatchConfig>>::into_te(sw_identity).is_none());

        // TE identity -> SW must fail
        let te_identity = EdwardsAffine::zero();
        assert!(te_to_sw::<BandersnatchConfig>(&te_identity).is_none());
        assert!(<EdwardsAffine as SWMapping<BandersnatchConfig>>::into_sw(te_identity).is_none());
    }

    /// The accumulator seed of this suite is outside the prime-order subgroup,
    /// so a key commitment that passes checked decoding can still make the
    /// sum of the ring backend have no affine form.
    #[cfg(feature = "ring")]
    #[test]
    fn exceptional_key_commitment_in_subgroup_rejected() {
        use crate::ring::RingSuite;
        use ark_ec::twisted_edwards::TECurveConfig;
        use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq};
        use ark_ff::{Field, One};
        use ark_serialize::Valid;

        let seed = ThisSuite::ACCUMULATOR_BASE.into_te().unwrap();
        let (a, d) = (BandersnatchConfig::COEFF_A, BandersnatchConfig::COEFF_D);
        // The sum has no affine form for x * y = k. With y = k / x, the curve
        // equation a * x^2 + y^2 = 1 + d * x^2 * y^2 is a quadratic in x^2.
        let k = (d * seed.x * seed.y).inverse().unwrap();
        let b = Fq::one() + d * k.square();
        let root = (b.square() - Fq::from(4u8) * a * k.square())
            .sqrt()
            .unwrap();
        let point = [b + root, b - root]
            .into_iter()
            .filter_map(|x_square| (x_square / (a + a)).sqrt())
            .flat_map(|x| [x, -x])
            .map(|x| EdwardsAffine::new_unchecked(x, k / x))
            .find(|p| p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
            .unwrap();
        let key_commitment = te_to_sw::<BandersnatchConfig>(&point).unwrap();
        assert!(key_commitment.check().is_ok());
        crate::ring::testing::batch_rejects_key_commitment::<ThisSuite>(key_commitment);
    }
}
