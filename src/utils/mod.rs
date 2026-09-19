//! # Common utilities
//!
//! This module provides cryptographic utility functions and curve mappings used
//! throughout the VRF implementations.

pub mod common;
pub mod hash_to_curve;
pub mod straus;
pub mod te_sw_map;
pub mod transcript;

pub(crate) mod canonical;

/// Standard cryptographic procedures.
///
/// Includes challenge generation, nonce derivation, and point-to-hash conversions
/// inspired by RFC-9381 and RFC-8032.
pub use common::*;

/// Hash-to-curve implementations (TAI, Elligator2 with XMD/XOF).
pub use hash_to_curve::*;

/// Twisted Edwards to Short Weierstrass curve mapping.
///
/// Provides bidirectional mappings between different curve representations,
/// allowing operations to be performed in the most convenient form.
pub use te_sw_map::*;

/// Fiat-Shamir transcript abstraction.
pub use transcript::*;

/// Point scalar multiplication with optional secret splitting.
///
/// When the `secret-split` feature is enabled, this macro splits the secret scalar
/// into the sum of two randomly generated scalars that retain the same sum. This
/// technique provides side-channel resistance at the cost of doubling the number
/// of scalar multiplications.
///
/// Without the feature enabled, it performs a standard scalar multiplication.
///
/// Neither form is constant time, see the timing note on `Secret`.
mod secret_split {
    #[cfg(feature = "secret-split")]
    macro_rules! smul {
        ($p:expr, $s:expr) => {{
            #[inline(always)]
            fn get_rand<T: ark_std::UniformRand>(_: &T) -> T {
                T::rand(&mut ark_std::rand::rngs::OsRng)
            }
            let mut x1 = get_rand(&$s);
            let mut x2 = $s - x1;
            let result = $p * x1 + $p * x2;
            zeroize::Zeroize::zeroize(&mut x1);
            zeroize::Zeroize::zeroize(&mut x2);
            result
        }};
    }

    #[cfg(not(feature = "secret-split"))]
    macro_rules! smul {
        ($p:expr, $s:expr) => {
            $p * $s
        };
    }

    pub(crate) use smul;
}
pub(crate) use secret_split::smul;
