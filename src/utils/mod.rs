//! Common utilities

pub mod common;
pub mod te_sw_map;

/// Standard procedures.
pub use common::*;
/// Twisted Edwards to Short Weierstrass mapping.
pub use te_sw_map::*;

use crate::{AffinePoint, ScalarField, Suite};
use ark_ec::AffineRepr;

type Projective<S> = <AffinePoint<S> as AffineRepr>::Group;

/// Point scalar multiplication with secret splitting.
///
/// Secret scalar split into the sum of two scalars, which randomly mutate but
/// retain the same sum. Incurs 2x penalty in scalar multiplications, but provides
/// side channel defenses.
#[cfg(feature = "secret-split")]
#[inline(always)]
pub(crate) fn mul_secret<S: Suite>(p: AffinePoint<S>, s: ScalarField<S>) -> Projective<S> {
    use ark_std::UniformRand;
    let mut rng = ark_std::rand::rngs::OsRng;
    let x1 = ScalarField::<S>::rand(&mut rng);
    let x2 = s - x1;
    p * x1 + p * x2
}

/// Point scalar multiplication with no secret splitting.
#[cfg(not(feature = "secret-split"))]
#[inline(always)]
pub(crate) fn mul_secret<S: Suite>(p: AffinePoint<S>, s: ScalarField<S>) -> Projective<S> {
    p * s
}
