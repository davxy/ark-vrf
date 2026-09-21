//! Hash-to-curve implementations.
//!
//! Provides Try-And-Increment (TAI) and Elligator2 hash-to-curve methods
//! following RFC 9380 and RFC 9381.

use crate::utils::transcript::Transcript;
use crate::*;
use ark_ec::{
    AffineRepr,
    hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map},
};
use ark_ff::field_hashers::HashToField;
use ark_std::vec;
use core::marker::PhantomData;

use super::common::DomSep;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Try-And-Increment hash-to-curve, inspired by RFC-9381 section 5.4.1.1.
///
/// 1. Absorbs `SUITE_ID || DomSep::HashToCurve || len(data) || data || ctr`
///    into the suite transcript and squeezes a candidate value. The data
///    length is encoded as a little-endian `u64` to keep the encoding
///    unambiguous regardless of `data` length.
/// 2. Attempts to interpret the squeezed bytes as a curve point via
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
    prefix.absorb_raw(&[DomSep::HashToCurve as u8]);
    prefix.absorb_raw(&(data.len() as u64).to_le_bytes());
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
/// Domain Separation Tag is `S::SUITE_ID || DomSep::HashToCurve`, mirroring the
/// per-operation tagging used by transcript-based paths.
fn hash_to_curve_ell2<S: Suite, H2F>(data: &[u8]) -> Option<AffinePoint<S>>
where
    H2F: HashToField<BaseField<S>>,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};

    let dst = [S::SUITE_ID, &[DomSep::HashToCurve as u8]].concat();
    MapToCurveBasedHasher::<
        <AffinePoint<S> as AffineRepr>::Group,
        H2F,
        Elligator2Map<CurveConfig<S>>,
    >::new(&dst)
    .and_then(|hasher| hasher.hash(data))
    .ok()
}

/// Elligator2 hash-to-curve using `expand_message_xmd` (RFC 9380 section 5.3.1).
///
/// Uses a fixed-output hash (e.g. SHA-512) for field element expansion.
/// Any salting of `data` must be applied by the caller.
///
/// `SEC_PARAM` must equal [`Suite::SECURITY_PARAMETER`], checked at compile
/// time: the arkworks field hasher takes it as a const generic, which generic
/// code cannot fill from a suite constant. Call it as
/// `hash_to_curve_ell2_xmd::<Self, H, { Self::SECURITY_PARAMETER }>`.
pub fn hash_to_curve_ell2_xmd<S: Suite, H, const SEC_PARAM: usize>(
    data: &[u8],
) -> Option<AffinePoint<S>>
where
    H: digest::FixedOutputReset + Default + Clone,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ff::field_hashers::DefaultFieldHasher;
    const {
        assert!(
            SEC_PARAM == S::SECURITY_PARAMETER,
            "SEC_PARAM must equal Suite::SECURITY_PARAMETER"
        )
    };
    hash_to_curve_ell2::<S, DefaultFieldHasher<H, SEC_PARAM>>(data)
}

/// XOF-based field hasher implementing `expand_message_xof` from RFC 9380 section 5.3.2.
///
/// Used with `MapToCurveBasedHasher` for hash-to-curve with extendable output functions
/// like BLAKE3 and SHAKE128. The expansion length follows
/// [`Suite::SECURITY_PARAMETER`].
struct XofFieldHasher<H, S> {
    dst: Vec<u8>,
    len_per_base_elem: usize,
    _marker: PhantomData<(H, S)>,
}

impl<F, H, S> HashToField<F> for XofFieldHasher<H, S>
where
    F: ark_ff::Field,
    H: digest::ExtendableOutput + Default + Clone,
    S: Suite,
{
    fn new(dst: &[u8]) -> Self {
        assert!(dst.len() <= 255, "DST longer than 255 bytes");
        let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
        let len_per_base_elem = (base_field_size_in_bits + S::SECURITY_PARAMETER).div_ceil(8);
        Self {
            dst: dst.to_vec(),
            len_per_base_elem,
            _marker: PhantomData,
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
    hash_to_curve_ell2::<S, XofFieldHasher<H, S>>(data)
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

    /// A suite at 256 bits expands more bytes per field element, so its
    /// Elligator2 points differ from the 128 bit ones on both expansion
    /// paths and stay in the prime order subgroup.
    #[cfg(feature = "bandersnatch")]
    #[test]
    fn ell2_follows_security_parameter() {
        use crate::suites::bandersnatch::BandersnatchSha512Ell2 as Narrow;
        use crate::utils::DigestXof;

        #[derive(Copy, Clone)]
        struct Wide;

        impl Suite for Wide {
            const SUITE_ID: &'static [u8] = <Narrow as Suite>::SUITE_ID;
            const SECURITY_PARAMETER: usize = 256;
            type Affine = <Narrow as Suite>::Affine;
            type Transcript = <Narrow as Suite>::Transcript;
        }

        let narrow =
            hash_to_curve_ell2_xmd::<Narrow, sha2::Sha512, { Narrow::SECURITY_PARAMETER }>(b"data")
                .unwrap();
        let wide =
            hash_to_curve_ell2_xmd::<Wide, sha2::Sha512, { Wide::SECURITY_PARAMETER }>(b"data")
                .unwrap();
        assert_ne!(narrow, wide);
        assert!(wide.is_on_curve() && wide.is_in_correct_subgroup_assuming_on_curve());

        type Xof = DigestXof<sha2::Sha512>;
        let narrow = hash_to_curve_ell2_xof::<Narrow, Xof>(b"data").unwrap();
        let wide = hash_to_curve_ell2_xof::<Wide, Xof>(b"data").unwrap();
        assert_ne!(narrow, wide);
        assert!(wide.is_on_curve() && wide.is_in_correct_subgroup_assuming_on_curve());
    }
}
