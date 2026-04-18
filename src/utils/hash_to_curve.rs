//! Hash-to-curve implementations.
//!
//! Provides Try-And-Increment (TAI) and Elligator2 hash-to-curve methods
//! following RFC 9380 and RFC 9381.

use crate::utils::SECURITY_PARAMETER;
use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::{
    AffineRepr,
    hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map},
};
use ark_ff::field_hashers::HashToField;
use ark_std::vec;

use super::common::DomSep;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Try-And-Increment hash-to-curve, inspired by RFC-9381 section 5.4.1.1.
///
/// 1. Hashes `suite_id || 0x01 || data || ctr || 0x00` using the suite transcript.
/// 2. Attempts to interpret the hash output as a curve point via
///    [`AffineRepr::from_random_bytes`].
/// 3. Clears the cofactor and checks the point is not the identity.
/// 4. Repeats with an incremented counter (up to 256 attempts) if no valid
///    point is found.
///
/// Returns `None` if no valid point is found after 256 attempts.
pub fn hash_to_curve_tai<S: Suite>(data: &[u8]) -> Option<AffinePoint<S>> {
    let base_len = BaseField::<S>::default().serialized_size(ark_serialize::Compress::Yes);
    let mut hash_buf = [0u8; 128];
    let hash = &mut hash_buf[..base_len];

    let mut prefix = S::Transcript::new(S::SUITE_ID);
    prefix.absorb_raw(&[DomSep::HashToCurveTai as u8]);
    prefix.absorb_raw(data);

    for ctr in 0..=255_u8 {
        let mut t = prefix.clone();
        t.absorb_raw(&[ctr]);
        t.squeeze_raw(hash);
        let Some(pt) = AffinePoint::<S>::from_random_bytes(hash) else {
            continue;
        };
        let pt = pt.clear_cofactor();
        if !pt.is_zero() {
            return Some(pt);
        }
    }
    None
}

/// Elligator2 hash-to-curve generic over the field hasher.
///
/// Both [`hash_to_curve_ell2_xmd`] and [`hash_to_curve_ell2_xof`] delegate to this,
/// differing only in the `H2F` type parameter (`DefaultFieldHasher` vs `XofFieldHasher`).
///
/// Uses `S::SUITE_ID` as the Domain Separation Tag for the hash-to-curve operation.
fn hash_to_curve_ell2<S: Suite, H2F>(data: &[u8]) -> Option<AffinePoint<S>>
where
    H2F: HashToField<BaseField<S>>,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};

    MapToCurveBasedHasher::<
        <AffinePoint<S> as AffineRepr>::Group,
        H2F,
        Elligator2Map<CurveConfig<S>>,
    >::new(S::SUITE_ID)
    .and_then(|hasher| hasher.hash(data))
    .ok()
}

/// Elligator2 hash-to-curve using `expand_message_xmd` (RFC 9380 section 5.3.1).
///
/// Uses a fixed-output hash (e.g. SHA-512) for field element expansion.
/// Any salting of `data` must be applied by the caller.
pub fn hash_to_curve_ell2_xmd<S: Suite, H>(data: &[u8]) -> Option<AffinePoint<S>>
where
    H: digest::FixedOutputReset + Default + Clone,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ff::field_hashers::DefaultFieldHasher;
    hash_to_curve_ell2::<S, DefaultFieldHasher<H, SECURITY_PARAMETER>>(data)
}

/// XOF-based field hasher implementing `expand_message_xof` from RFC 9380 section 5.3.2.
///
/// Used with `MapToCurveBasedHasher` for hash-to-curve with extendable output functions
/// like BLAKE3 and SHAKE128.
struct XofFieldHasher<
    H: digest::ExtendableOutput + Default + Clone,
    const SEC_PARAM: usize = SECURITY_PARAMETER,
> {
    dst: Vec<u8>,
    len_per_base_elem: usize,
    _marker: core::marker::PhantomData<H>,
}

impl<F: ark_ff::Field, H: digest::ExtendableOutput + Default + Clone, const SEC_PARAM: usize>
    HashToField<F> for XofFieldHasher<H, SEC_PARAM>
{
    fn new(dst: &[u8]) -> Self {
        assert!(dst.len() <= 255, "DST longer than 255 bytes");
        let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
        let len_per_base_elem = (base_field_size_in_bits + SEC_PARAM).div_ceil(8);
        Self {
            dst: dst.to_vec(),
            len_per_base_elem,
            _marker: core::marker::PhantomData,
        }
    }

    fn hash_to_field<const N: usize>(&self, msg: &[u8]) -> [F; N] {
        use digest::XofReader;
        let m = F::extension_degree() as usize;
        let len_in_bytes = N * m * self.len_per_base_elem;
        assert!(len_in_bytes <= 65535, "len_in_bytes exceeds 65535");
        // expand_message_xof: H(msg || I2OSP(len, 2) || DST || I2OSP(len(DST), 1))
        let mut h = H::default();
        h.update(msg);
        h.update(&(len_in_bytes as u16).to_be_bytes());
        h.update(&self.dst);
        h.update(&[self.dst.len() as u8]);
        let mut uniform_bytes = vec![0u8; len_in_bytes];
        h.finalize_xof().read(&mut uniform_bytes);
        ark_std::array::from_fn::<F, N, _>(|i| {
            let base_prime_field_elem = |j: usize| {
                let elm_offset = self.len_per_base_elem * (j + i * m);
                F::BasePrimeField::from_be_bytes_mod_order(
                    &uniform_bytes[elm_offset..][..self.len_per_base_elem],
                )
            };
            F::from_base_prime_field_elems((0..m).map(base_prime_field_elem)).unwrap()
        })
    }
}

/// Elligator2 hash-to-curve using an XOF (extendable output function).
///
/// Uses `expand_message_xof` (RFC 9380 section 5.3.2) for field element expansion.
/// This is the natural expansion mode for XOF hash functions like BLAKE3 and SHAKE128.
/// Any salting of `data` must be applied by the caller.
pub fn hash_to_curve_ell2_xof<S: Suite, H>(data: &[u8]) -> Option<AffinePoint<S>>
where
    H: digest::ExtendableOutput + Default + Clone,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    hash_to_curve_ell2::<S, XofFieldHasher<H, SECURITY_PARAMETER>>(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suites::testing::TestSuite;

    #[test]
    fn hash_to_curve_tai_works() {
        let pt = hash_to_curve_tai::<TestSuite>(b"hello world").unwrap();
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }
}
