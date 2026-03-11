//! Suite for testing

use super::{SuiteId, curve, h2c, hash};
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: SuiteId = SuiteId::new(1, curve::TESTING, hash::SHA256, h2c::TAI);
    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "17942753914942854312926570463413775812691829308325260880005040354031058739531"
        );
        const Y: BaseField = MontFp!(
            "48163615609123823054157253982000584113789967295281127409467833823120845118557"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);

impl crate::testing::SuiteExt for TestSuite {
    const SUITE_NAME: &str = "testing_sha-256_tai";
}

#[cfg(test)]
mod tests {
    use super::*;
    ietf_suite_tests!(TestSuite);
    pedersen_suite_tests!(TestSuite);
    thin_suite_tests!(TestSuite);
}
