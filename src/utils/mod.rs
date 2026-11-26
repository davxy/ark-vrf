//! # Utilities
//!
//! Hashing, transcripts and curve maps of the schemes.

pub mod common;
pub mod hash_to_curve;
pub mod straus;
pub mod te_sw_map;
pub mod transcript;

pub(crate) mod canonical;

pub use common::*;
pub use hash_to_curve::*;
pub use te_sw_map::*;
pub use transcript::*;

/// `smul!`: scalar multiplication by a secret. With `secret-split`, it uses two
/// random shares of the scalar (see the crate docs). Neither form is constant
/// time.
mod secret_split {
    #[cfg(feature = "secret-split")]
    macro_rules! smul {
        ($p:expr, $s:expr) => {{
            #[inline(always)]
            fn get_rand<T: ark_std::UniformRand>(_: &T) -> T {
                T::rand(&mut rand::rngs::OsRng)
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
