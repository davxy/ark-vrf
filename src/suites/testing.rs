//! Suite for testing

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"Testing_SHA-256_TAI";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "55796432992313178130943166032098615698323779464960409153950097760136172959634"
        );
        const Y: BaseField =
            MontFp!("4697052430764732321227694573644607884798525818653590884850734528949659500180");
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);

impl crate::testing::SuiteExt for TestSuite {}

#[cfg(test)]
mod tests {
    use super::*;
    codec_suite_tests!(TestSuite);
    ietf_suite_tests!(TestSuite);
    pedersen_suite_tests!(TestSuite);
    thin_suite_tests!(TestSuite);
}
