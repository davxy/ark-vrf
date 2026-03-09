//! Suite for testing

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"Testing_SHA-256_TAI";
    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "5477687224379464434972397475173922127513070182596494094025530052162096206304"
        );
        const Y: BaseField = MontFp!(
            "9172565768957182840993570105344204954102057020640798540535539704135195545294"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);

impl crate::testing::SuiteExt for TestSuite {}

#[cfg(test)]
mod tests {
    use super::*;
    ietf_suite_tests!(TestSuite);
    pedersen_suite_tests!(TestSuite);
    thin_suite_tests!(TestSuite);
}
