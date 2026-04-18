#![allow(unused_macros, dead_code)]

use ark_vrf::Suite;

pub trait SuiteExt: Suite {
    const NAME: &'static str = match core::str::from_utf8(Self::SUITE_ID) {
        Ok(s) => s,
        Err(_) => panic!("Suite::SUITE_ID is not valid UTF-8"),
    };
}

impl<T: Suite> SuiteExt for T {}

/// Dispatches a benchmark function for all enabled suites.
macro_rules! for_each_suite {
    ($c:expr, $fn:ident) => {
        #[cfg(feature = "bandersnatch")]
        $fn::<ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2>($c);
        #[cfg(all(feature = "bandersnatch", feature = "shake128"))]
        $fn::<ark_vrf::suites::bandersnatch_shake128::BandersnatchShake128Ell2>($c);
        #[cfg(feature = "jubjub")]
        $fn::<ark_vrf::suites::jubjub::JubJubSha512Tai>($c);
        #[cfg(feature = "baby-jubjub")]
        $fn::<ark_vrf::suites::baby_jubjub::BabyJubJubSha512Tai>($c);
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
        $fn::<ark_vrf::suites::jubjub::JubJubSha512Tai>($c);
        #[cfg(feature = "baby-jubjub")]
        $fn::<ark_vrf::suites::baby_jubjub::BabyJubJubSha512Tai>($c);
    };
}
