use crate::*;
use ark_ec::{
    short_weierstrass::{Affine as WeierstrassAffine, SWCurveConfig},
    twisted_edwards::{Affine as EdwardsAffine, MontCurveConfig, TECurveConfig},
    CurveConfig,
};
use ark_ff::{Field, One};
use ark_std::borrow::Cow;

// Constants used in mapping TE form to SW form and vice versa
pub trait MapConfig: TECurveConfig + SWCurveConfig + MontCurveConfig {
    const MONT_A_OVER_THREE: <Self as CurveConfig>::BaseField;
    const MONT_B_INV: <Self as CurveConfig>::BaseField;
}

pub fn map_sw_to_te<C: MapConfig>(point: &WeierstrassAffine<C>) -> Option<EdwardsAffine<C>> {
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

    Some(EdwardsAffine::new_unchecked(v, w))
}

pub fn map_te_to_sw<C: MapConfig>(point: &EdwardsAffine<C>) -> Option<WeierstrassAffine<C>> {
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

    Some(WeierstrassAffine::new_unchecked(x, y))
}

pub trait SWMapping<C: ark_ec::short_weierstrass::SWCurveConfig> {
    fn from_sw(sw: ark_ec::short_weierstrass::Affine<C>) -> Self;
    fn into_sw(&self) -> Cow<ark_ec::short_weierstrass::Affine<C>>;
}

impl<C: ark_ec::short_weierstrass::SWCurveConfig> SWMapping<C>
    for ark_ec::short_weierstrass::Affine<C>
{
    #[inline(always)]
    fn from_sw(sw: ark_ec::short_weierstrass::Affine<C>) -> Self {
        sw
    }

    #[inline(always)]
    fn into_sw(&self) -> Cow<ark_ec::short_weierstrass::Affine<C>> {
        Cow::Borrowed(self)
    }
}

impl<C: MapConfig> SWMapping<C> for ark_ec::twisted_edwards::Affine<C> {
    #[inline(always)]
    fn from_sw(sw: ark_ec::short_weierstrass::Affine<C>) -> Self {
        const ERR_MSG: &str =
            "SW to TE is expected to be implemented only for curves supporting the mapping";
        map_sw_to_te(&sw).expect(ERR_MSG)
    }

    #[inline(always)]
    fn into_sw(&self) -> Cow<ark_ec::short_weierstrass::Affine<C>> {
        const ERR_MSG: &str =
            "TE to SW is expected to be implemented only for curves supporting the mapping";
        Cow::Owned(map_te_to_sw(&self).expect(ERR_MSG))
    }
}

pub(crate) trait SWMappingSeq<C: ark_ec::short_weierstrass::SWCurveConfig> {
    #[inline(always)]
    fn into_sw_seq(&self) -> Cow<[ark_ec::short_weierstrass::Affine<C>]>;
}

impl<C: SWCurveConfig> SWMappingSeq<C> for [ark_ec::short_weierstrass::Affine<C>]
where
    ark_ec::short_weierstrass::Affine<C>: SWMapping<C>,
{
    #[inline(always)]
    fn into_sw_seq(&self) -> Cow<[ark_ec::short_weierstrass::Affine<C>]> {
        Cow::Borrowed(self)
    }
}

impl<C: MapConfig> SWMappingSeq<C> for [ark_ec::twisted_edwards::Affine<C>]
where
    ark_ec::twisted_edwards::Affine<C>: SWMapping<C>,
{
    #[inline(always)]
    fn into_sw_seq(&self) -> Cow<[WeierstrassAffine<C>]> {
        #[cfg(feature = "parallel")]
        use rayon::prelude::*;

        const ERR_MSG: &str =
            "TE to SW is expected to be implemented only for curves supporting the mapping";
        #[cfg(feature = "parallel")]
        let pks: Vec<_> = self
            .par_iter()
            .map(|p| map_te_to_sw(p).expect(ERR_MSG))
            .collect();
        #[cfg(not(feature = "parallel"))]
        let pks: Vec<_> = self
            .iter()
            .map(|p| map_te_to_sw(p).expect(ERR_MSG))
            .collect();
        Cow::Owned(pks)
    }
}
