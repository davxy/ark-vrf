#![allow(unused_macros, dead_code)]

use ark_vrf::Suite;

/// Provides human-readable names for benchmark output.
pub trait BenchInfo: Suite {
    const SUITE_NAME: &'static str;
    const DATA_TO_POINT_TAG: &'static str;
    const CHALLENGE_TAG: &'static str;
    const POINT_TO_HASH_TAG: &'static str;
    const NONCE_TAG: &'static str;

    fn print_info() {
        println!("\n---------------------------------------------------------------");
        println!("suite_name: {}", Self::SUITE_NAME,);
        println!("suite_id: {}", String::from_utf8_lossy(Self::SUITE_ID));
        println!("data_to_point (h2c): {}", Self::DATA_TO_POINT_TAG);
        println!("challenge: {}", Self::CHALLENGE_TAG);
        println!("point_to_hash: {}", Self::POINT_TO_HASH_TAG);
        println!("nonce: {}", Self::NONCE_TAG);
        println!("---------------------------------------------------------------\n");
    }
}

#[cfg(feature = "bandersnatch")]
impl BenchInfo for ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2 {
    const SUITE_NAME: &'static str = "bandersnatch";
    const DATA_TO_POINT_TAG: &'static str = "ell2_rfc_9380";
    const CHALLENGE_TAG: &'static str = "rfc_9381";
    const POINT_TO_HASH_TAG: &'static str = "rfc_9381";
    const NONCE_TAG: &'static str = "rfc_8032";
}

#[cfg(feature = "jubjub")]
impl BenchInfo for ark_vrf::suites::jubjub::JubJubSha512Ell2 {
    const SUITE_NAME: &'static str = "jubjub";
    const DATA_TO_POINT_TAG: &'static str = "tai_rfc_9381";
    const CHALLENGE_TAG: &'static str = "rfc_9381";
    const POINT_TO_HASH_TAG: &'static str = "rfc_9381";
    const NONCE_TAG: &'static str = "rfc_8032";
}

#[cfg(feature = "baby-jubjub")]
impl BenchInfo for ark_vrf::suites::baby_jubjub::BabyJubJubSha512Ell2 {
    const SUITE_NAME: &'static str = "baby-jubjub";
    const DATA_TO_POINT_TAG: &'static str = "tai_rfc_9381";
    const CHALLENGE_TAG: &'static str = "rfc_9381";
    const POINT_TO_HASH_TAG: &'static str = "rfc_9381";
    const NONCE_TAG: &'static str = "rfc_8032";
}

#[cfg(feature = "ed25519")]
impl BenchInfo for ark_vrf::suites::ed25519::Ed25519Sha512Tai {
    const SUITE_NAME: &'static str = "ed25519";
    const DATA_TO_POINT_TAG: &'static str = "tai_rfc_9381";
    const CHALLENGE_TAG: &'static str = "rfc_9381";
    const POINT_TO_HASH_TAG: &'static str = "rfc_9381";
    const NONCE_TAG: &'static str = "rfc_8032";
}

#[cfg(feature = "secp256r1")]
impl BenchInfo for ark_vrf::suites::secp256r1::Secp256r1Sha256Tai {
    const SUITE_NAME: &'static str = "secp256r1";
    const DATA_TO_POINT_TAG: &'static str = "tai_rfc_9381";
    const CHALLENGE_TAG: &'static str = "rfc_9381";
    const POINT_TO_HASH_TAG: &'static str = "rfc_9381";
    const NONCE_TAG: &'static str = "rfc_6979";
}

/// Dispatches a benchmark function for all enabled suites.
macro_rules! for_each_suite {
    ($c:expr, $fn:ident) => {
        #[cfg(feature = "bandersnatch")]
        $fn::<ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2>($c);
        #[cfg(feature = "jubjub")]
        $fn::<ark_vrf::suites::jubjub::JubJubSha512Ell2>($c);
        #[cfg(feature = "baby-jubjub")]
        $fn::<ark_vrf::suites::baby_jubjub::BabyJubJubSha512Ell2>($c);
        #[cfg(feature = "ed25519")]
        $fn::<ark_vrf::suites::ed25519::Ed25519Sha512Tai>($c);
        #[cfg(feature = "secp256r1")]
        $fn::<ark_vrf::suites::secp256r1::Secp256r1Sha256Tai>($c);
    };
}

/// Dispatches a benchmark function for all enabled ring-capable suites.
macro_rules! for_each_ring_suite {
    ($c:expr, $fn:ident) => {
        #[cfg(feature = "bandersnatch")]
        $fn::<ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2>($c);
        #[cfg(feature = "jubjub")]
        $fn::<ark_vrf::suites::jubjub::JubJubSha512Ell2>($c);
        #[cfg(feature = "baby-jubjub")]
        $fn::<ark_vrf::suites::baby_jubjub::BabyJubJubSha512Ell2>($c);
    };
}
