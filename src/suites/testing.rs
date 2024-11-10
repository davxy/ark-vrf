//! Suite for testing

use crate::testing as common;
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"ark-ec-vrfs-testing";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed25519::EdwardsAffine;
    type Hasher = sha2::Sha256;
    type Codec = codec::ArkworksCodec;

    fn nonce(_sk: &ScalarField, _pt: Input) -> ScalarField {
        common::random_val(None)
    }
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("2842812182132742151291439804105987992770071362848070020835328675429531065386");
        const Y: BaseField = MontFp!(
            "51537589290258453714586392305999864217349499404270029291993413345863140891436"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);
suite_tests!(TestSuite);
