//! # ECVRF Bandersnatch SHA-512 Elligator2 suite
//!
//! With the shared rules of [`crate::suites`]. The
//! [Bandersnatch VRF specification](https://github.com/davxy/bandersnatch-vrf-spec)
//! recommends this version. Version 2, [`super::bandersnatch_v2`], pads
//! `expand_message_xmd` as RFC 9380 requires.
//!
//! - `SUITE_ID` = `b"Bandersnatch-SHA512-ELL2-v1"`.
//! - `G` is the prime-order subgroup of the Bandersnatch curve in twisted
//!   Edwards form, with the parameters of
//!   [MSZ21](https://eprint.iacr.org/2021/1152). `fLen` = `qLen` = 32 and
//!   `cofactor` = 4. The generator is:
//!   - `G.x` = 18886178867200960497001835917649091219057080094937609519140440539760939937304
//!   - `G.y` = 19188667384257783945677642223292697773471335439753913231509108946878080696678
//! - Hash: SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234)),
//!   `hLen` = 64.
//! - `ECVRF_encode_to_curve`: Elligator2 of
//!   [RFC 9380](https://datatracker.ietf.org/doc/rfc9380) section 6.8.2, with
//!   `expand_message_xmd` over SHA-512 (section 5.3.1) and
//!   `DST = SUITE_ID || DomSep::HashToCurve` (see
//!   [`crate::utils::hash_to_curve_ell2_xmd`]). The zero prefix `Z_pad` has 48
//!   bytes, the element length of the arkworks 0.6 `DefaultFieldHasher`, and not
//!   the 128 bytes of the SHA-512 block.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Bandersnatch in Twisted Edwards form, SHA-512, Elligator2 hash-to-curve.
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
        const SUITE_NAME: &str = "bandersnatch_sha-512_ell2";
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

    /// Arkworks reads the identity `(0, 1)` with either sign flag, since both
    /// roots of `x` are zero. The crate decoders accept the clear flag only.
    #[test]
    fn identity_has_one_encoding() {
        use crate::thin::Proof;
        use crate::utils::canonical::CanonicalDeserializeStrict;
        use ark_serialize::{Compress, Validate};

        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        let mut alias = canonical;
        alias[31] |= 0x80;

        let identity = AffinePoint::deserialize_compressed(&canonical[..]).unwrap();
        assert!(identity.is_zero());
        assert_eq!(
            AffinePoint::deserialize_compressed(&alias[..]).unwrap(),
            identity
        );

        let decode = |bytes: &[u8], validate| {
            AffinePoint::deserialize_strict(bytes, Compress::Yes, validate)
        };
        assert_eq!(decode(&canonical, Validate::No).unwrap(), identity);
        assert!(decode(&alias, Validate::No).is_err());
        assert_eq!(decode(&canonical, Validate::Yes).unwrap(), identity);
        assert!(decode(&alias, Validate::Yes).is_err());

        // A Thin proof is `R || s`; put the identity in `R`.
        let mut s = Vec::new();
        ScalarField::from(7u64)
            .serialize_compressed(&mut s)
            .unwrap();
        let canonical_proof = [&canonical[..], &s[..]].concat();
        let alias_proof = [&alias[..], &s[..]].concat();

        let reencode = |proof: Proof<ThisSuite>| {
            let mut bytes = Vec::new();
            proof.serialize_compressed(&mut bytes).unwrap();
            bytes
        };
        let unchecked = |bytes: &[u8]| Proof::<ThisSuite>::deserialize_compressed_unchecked(bytes);
        assert_eq!(
            reencode(unchecked(&canonical_proof).unwrap()),
            canonical_proof
        );
        assert!(unchecked(&alias_proof).is_err());

        let checked = |bytes: &[u8]| Proof::<ThisSuite>::deserialize_compressed(bytes);
        assert_eq!(
            reencode(checked(&canonical_proof).unwrap()),
            canonical_proof
        );
        assert!(checked(&alias_proof).is_err());
    }

    /// Canary for an arkworks defect: the BLS12-381 uncompressed decoder skips
    /// the on-curve test. When this fails, the `RingVerifierKey` caveat can go.
    #[test]
    fn arkworks_bls12_381_uncompressed_decode_skips_on_curve() {
        use ark_bls12_381::{Fq, G1Affine};
        use ark_ff::Field;
        use ark_serialize::Valid;

        let (x, y) = G1Affine::generator().xy().unwrap();
        let u = Fq::from(2u64);
        let off_curve = G1Affine::new_unchecked(x * u.square(), y * u.square() * u);
        assert!(!off_curve.is_on_curve());
        assert!(off_curve.is_in_correct_subgroup_assuming_on_curve());

        let mut bytes = Vec::new();
        off_curve.serialize_uncompressed(&mut bytes).unwrap();
        let decoded = G1Affine::deserialize_uncompressed(&bytes[..]).unwrap();
        assert_eq!(decoded, off_curve);
        assert!(decoded.check().is_err());
    }
}
