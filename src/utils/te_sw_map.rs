//! # Twisted Edwards to Short Weierstrass curve mapping utilities.
//!
//! This module provides bidirectional mappings between different curve representations,
//! allowing operations to be performed in the most convenient form for a given task.

use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, MontCurveConfig, TECurveConfig},
    CurveConfig,
};
use ark_ff::{Field, One};
use ark_std::borrow::Cow;

/// Constants used in mapping TE form to SW form and vice versa.
/// Configuration trait for curves that support mapping between representations.
///
/// This trait must be implemented for curves that need to be converted between
/// Twisted Edwards, Short Weierstrass, and Montgomery forms.
pub trait MapConfig: TECurveConfig + SWCurveConfig + MontCurveConfig {
    /// Precomputed value of Montgomery curve parameter A divided by 3.
    const MONT_A_OVER_THREE: <Self as CurveConfig>::BaseField;

    /// Precomputed inverse of Montgomery curve parameter B.
    const MONT_B_INV: <Self as CurveConfig>::BaseField;
}

/// Map a point in Short Weierstrass form into its corresponding point in Twisted Edwards form.
///
/// This function performs the conversion by first mapping from Short Weierstrass to Montgomery form,
/// then from Montgomery to Twisted Edwards form.
pub fn sw_to_te<C: MapConfig>(point: &SWAffine<C>) -> Option<TEAffine<C>> {
    // First map the point from SW to Montgomery
    // (Bx - A/3, By)
    let mx = <C as MontCurveConfig>::COEFF_B * point.x - C::MONT_A_OVER_THREE;
    let my = <C as MontCurveConfig>::COEFF_B * point.y;

    // Then we map the TE point to Montgamory
    // (x,y) -> (x/y,(x−1)/(x+1))
    let v_denom = my.inverse()?;
    let x_p_1 = mx + <<C as CurveConfig>::BaseField as One>::one();
    let w_denom = x_p_1.inverse()?;
    let v = mx * v_denom;
    let w = (mx - <<C as CurveConfig>::BaseField as One>::one()) * w_denom;

    Some(TEAffine::new_unchecked(v, w))
}

/// Map a point in Twisted Edwards form into its corresponding point in Short Weierstrass form.
///
/// This function performs the conversion by first mapping from Twisted Edwards to Montgomery form,
/// then from Montgomery to Short Weierstrass form.
pub fn te_to_sw<C: MapConfig>(point: &TEAffine<C>) -> Option<SWAffine<C>> {
    // Map from TE to Montgomery: (1+y)/(1-y), (1+y)/(x(1-y))
    let v_denom = <<C as CurveConfig>::BaseField as One>::one() - point.y;
    let w_denom = point.x - point.x * point.y;
    let v_denom_inv = v_denom.inverse()?;
    let w_denom_inv = w_denom.inverse()?;
    let v_w_num = <<C as CurveConfig>::BaseField as One>::one() + point.y;
    let v = v_w_num * v_denom_inv;
    let w = v_w_num * w_denom_inv;

    // Map Montgamory to SW: ((x+A/3)/B,y/B)
    let x = C::MONT_B_INV * (v + C::MONT_A_OVER_THREE);
    let y = C::MONT_B_INV * w;

    Some(SWAffine::new_unchecked(x, y))
}

/// Trait for types that can be converted from/to Short Weierstrass form.
///
/// This trait provides methods to convert between a type and its Short Weierstrass representation,
/// both for individual points and slices of points.
pub trait SWMapping<C: SWCurveConfig> {
    /// Convert a Short Weierstrass point to this type.
    fn from_sw(sw: SWAffine<C>) -> Self;

    /// Convert this type to a Short Weierstrass point.
    fn into_sw(self) -> SWAffine<C>;

    /// Convert a slice of this type to a slice of Short Weierstrass points.
    ///
    /// Returns a borrowed slice if no conversion is needed, or an owned
    /// vector if conversion is required.
    fn to_sw_slice(slice: &[Self]) -> Cow<[SWAffine<C>]>
    where
        Self: Sized;
}

impl<C: SWCurveConfig> SWMapping<C> for SWAffine<C> {
    #[inline(always)]
    fn from_sw(sw: SWAffine<C>) -> Self {
        sw
    }

    #[inline(always)]
    fn into_sw(self) -> SWAffine<C> {
        self
    }

    #[inline(always)]
    fn to_sw_slice(slice: &[Self]) -> Cow<[SWAffine<C>]> {
        Cow::Borrowed(slice)
    }
}

impl<C: MapConfig> SWMapping<C> for TEAffine<C> {
    #[inline(always)]
    fn from_sw(sw: SWAffine<C>) -> Self {
        sw_to_te(&sw).unwrap_or_default()
    }

    #[inline(always)]
    fn into_sw(self) -> SWAffine<C> {
        te_to_sw(&self).unwrap_or_default()
    }

    #[inline(always)]
    fn to_sw_slice(slice: &[Self]) -> Cow<[SWAffine<C>]> {
        let pks;
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            pks = slice.par_iter().map(|p| p.into_sw()).collect();
        }
        #[cfg(not(feature = "parallel"))]
        {
            pks = slice.iter().map(|p| p.into_sw()).collect();
        }
        Cow::Owned(pks)
    }
}

/// Trait for types that can be converted from/to Twisted Edwards form.
///
/// This trait provides methods to convert between a type and its Twisted Edwards representation,
/// both for individual points and slices of points.
pub trait TEMapping<C: TECurveConfig> {
    /// Convert a Twisted Edwards point to this type.
    fn from_te(te: TEAffine<C>) -> Self;

    /// Convert this type to a Twisted Edwards point.
    fn into_te(self) -> TEAffine<C>;

    /// Convert a slice of this type to a slice of Twisted Edwards points.
    ///
    /// Returns a borrowed slice if no conversion is needed, or an owned
    /// vector if conversion is required.
    fn to_te_slice(slice: &[Self]) -> Cow<[TEAffine<C>]>
    where
        Self: Sized;
}

impl<C: TECurveConfig> TEMapping<C> for TEAffine<C> {
    #[inline(always)]
    fn from_te(te: TEAffine<C>) -> Self {
        te
    }

    #[inline(always)]
    fn into_te(self) -> TEAffine<C> {
        self
    }

    #[inline(always)]
    fn to_te_slice(slice: &[Self]) -> Cow<[TEAffine<C>]> {
        Cow::Borrowed(slice)
    }
}

impl<C: MapConfig> TEMapping<C> for SWAffine<C> {
    #[inline(always)]
    fn from_te(te: TEAffine<C>) -> Self {
        te_to_sw(&te).unwrap_or_default()
    }

    #[inline(always)]
    fn into_te(self) -> TEAffine<C> {
        sw_to_te(&self).unwrap_or_default()
    }

    #[inline(always)]
    fn to_te_slice(slice: &[Self]) -> Cow<[TEAffine<C>]> {
        let pks;
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            pks = slice.par_iter().map(|p| p.into_te()).collect();
        }
        #[cfg(not(feature = "parallel"))]
        {
            pks = slice.iter().map(|p| p.into_te()).collect();
        }
        Cow::Owned(pks)
    }
}
