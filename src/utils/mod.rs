//! # Common utilities
//!
//! This module provides cryptographic utility functions and curve mappings used
//! throughout the VRF implementations.

pub mod common;
pub mod te_sw_map;

/// Standard cryptographic procedures.
///
/// Includes hash functions, challenge generation, and point-to-hash conversions
/// following RFC-9381 and other standards.
pub use common::*;

/// Twisted Edwards to Short Weierstrass curve mapping.
///
/// Provides bidirectional mappings between different curve representations,
/// allowing operations to be performed in the most convenient form.
pub use te_sw_map::*;

/// Point scalar multiplication with optional secret splitting.
///
/// When the `secret-split` feature is enabled, this macro splits the secret scalar
/// into the sum of two randomly generated scalars that retain the same sum. This
/// technique provides side-channel resistance at the cost of doubling the number
/// of scalar multiplications.
///
/// Without the feature enabled, it performs a standard scalar multiplication.
mod secret_split {
    #[cfg(feature = "secret-split")]
    #[doc(hidden)]
    #[macro_export]
    macro_rules! smul {
        ($p:expr, $s:expr) => {{
            #[inline(always)]
            fn get_rand<T: ark_std::UniformRand>(_: &T) -> T {
                T::rand(&mut ark_std::rand::rngs::OsRng)
            }
            let x1 = get_rand(&$s);
            let x2 = $s - x1;
            $p * x1 + $p * x2
        }};
    }

    #[cfg(not(feature = "secret-split"))]
    #[doc(hidden)]
    #[macro_export]
    macro_rules! smul {
        ($p:expr, $s:expr) => {
            $p * $s
        };
    }
}
