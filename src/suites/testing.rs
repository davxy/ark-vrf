//! Suite for testing

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"Testing-SHA256-TAI-v1";
    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("3310617998588019043596181043598335786888094217571323926547956053100032777190");
        const Y: BaseField = MontFp!(
            "16824531136491949759823061604778551593864344614632277377095388820423530178202"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);

impl crate::testing::SuiteExt for TestSuite {
    const SUITE_NAME: &str = "testing_sha-256_tai";
}

/// Suite at another security level. Every width must follow
/// `Suite::SECURITY_PARAMETER`; no vector exists for it.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite256;

impl Suite for TestSuite256 {
    const SUITE_ID: &'static [u8] = b"Testing-SHA256-TAI-256-v1";
    const SECURITY_PARAMETER: usize = 256;
    type Affine = ark_ed25519::EdwardsAffine;
    type Transcript = utils::HashTranscript<sha2::Sha256>;
}

impl PedersenSuite for TestSuite256 {
    const BLINDING_BASE: crate::AffinePoint<Self> = <TestSuite as PedersenSuite>::BLINDING_BASE;
}

#[cfg(test)]
mod tests {
    use super::*;
    suite_tests!(TestSuite);
    tiny_suite_tests!(TestSuite);
    pedersen_suite_tests!(TestSuite);
    thin_suite_tests!(TestSuite);

    /// The generic scheme tests at 256 bits: prove, verify and batch verify
    /// with 32 byte challenges and 64 byte nonce expansion.
    mod wide {
        use super::TestSuite256;

        #[test]
        fn tiny_prove_verify_multi() {
            crate::tiny::testing::prove_verify_multi::<TestSuite256>();
        }

        #[test]
        fn thin_batch_verify() {
            crate::thin::testing::batch_verify::<TestSuite256>();
        }

        #[test]
        fn pedersen_batch_verify() {
            crate::pedersen::testing::batch_verify::<TestSuite256>();
        }
    }
}
