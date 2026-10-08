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
/// differing only in the `H2F` type parameter (`XmdFieldHasher` vs `XofFieldHasher`).
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

    const {
        assert!(
            S::SUITE_ID.len() < 255,
            "SUITE_ID must be shorter than 255 bytes for the Elligator2 DST"
        )
    };
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
pub fn hash_to_curve_ell2_xmd<S: Suite, H>(data: &[u8]) -> Option<AffinePoint<S>>
where
    H: digest::FixedOutputReset + digest::core_api::BlockSizeUser + Default + Clone,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    hash_to_curve_ell2::<S, XmdFieldHasher<H, S, Rfc9380>>(data)
}

/// [`hash_to_curve_ell2_xmd`] with the `Z_pad` of the arkworks 0.6
/// `DefaultFieldHasher`, kept for the deprecated `bandersnatch_v1` suite.
#[cfg(feature = "bandersnatch")]
pub(crate) fn hash_to_curve_ell2_xmd_arkworks_compat<S: Suite, H>(
    data: &[u8],
) -> Option<AffinePoint<S>>
where
    H: digest::FixedOutputReset + digest::core_api::BlockSizeUser + Default + Clone,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    hash_to_curve_ell2::<S, XmdFieldHasher<H, S, ArkworksCompat>>(data)
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

/// Length of the `Z_pad` prefix of `expand_message_xmd`.
trait XmdPadding {
    /// Length in bytes, given the expanded length of one base field element.
    fn z_pad_len<H: digest::core_api::BlockSizeUser>(len_per_base_elem: usize) -> usize;
}

/// `Z_pad` of RFC 9380 section 5.3.1: the input block size of the hash.
struct Rfc9380;

impl XmdPadding for Rfc9380 {
    fn z_pad_len<H: digest::core_api::BlockSizeUser>(_len_per_base_elem: usize) -> usize {
        H::block_size()
    }
}

/// `Z_pad` of the arkworks 0.6 `DefaultFieldHasher`: the expanded element
/// length. Not RFC 9380 compliant when this length differs from the block
/// size.
///
/// Arkworks fixes this in <https://github.com/arkworks-rs/algebra/pull/1140>.
/// After that release, `DefaultFieldHasher` matches [`Rfc9380`] and not this
/// type.
#[cfg(any(test, feature = "bandersnatch"))]
struct ArkworksCompat;

#[cfg(any(test, feature = "bandersnatch"))]
impl XmdPadding for ArkworksCompat {
    fn z_pad_len<H: digest::core_api::BlockSizeUser>(len_per_base_elem: usize) -> usize {
        len_per_base_elem
    }
}

/// Field hasher implementing `expand_message_xmd` from RFC 9380 section 5.3.1.
///
/// The expansion length follows [`Suite::SECURITY_PARAMETER`].
struct XmdFieldHasher<H, S, P> {
    dst: Vec<u8>,
    len_per_base_elem: usize,
    _marker: PhantomData<(H, S, P)>,
}

impl<F, H, S, P> HashToField<F> for XmdFieldHasher<H, S, P>
where
    F: ark_ff::Field,
    H: digest::FixedOutputReset + digest::core_api::BlockSizeUser + Default + Clone,
    S: Suite,
    P: XmdPadding,
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
        let m = F::extension_degree() as usize;
        let len_in_bytes = N * m * self.len_per_base_elem;
        let hash_len = <H as digest::OutputSizeUser>::output_size();
        let ell = len_in_bytes.div_ceil(hash_len);
        assert!(ell <= 255, "ell exceeds 255");
        assert!(len_in_bytes <= 65535, "len_in_bytes exceeds 65535");
        let dst_prime = [&self.dst[..], &[self.dst.len() as u8]].concat();

        let mut h = H::default();
        h.update(&vec![0u8; P::z_pad_len::<H>(self.len_per_base_elem)]);
        h.update(msg);
        h.update(&(len_in_bytes as u16).to_be_bytes());
        h.update(&[0]);
        h.update(&dst_prime);
        let b_0 = h.finalize_fixed_reset();

        h.update(&b_0);
        h.update(&[1]);
        h.update(&dst_prime);
        let mut b_i = h.finalize_fixed_reset();

        let mut uniform_bytes = Vec::with_capacity(ell * hash_len);
        uniform_bytes.extend_from_slice(&b_i);
        for i in 2..=ell {
            let xored: Vec<u8> = b_0.iter().zip(b_i.iter()).map(|(l, r)| l ^ r).collect();
            h.update(&xored);
            h.update(&[i as u8]);
            h.update(&dst_prime);
            b_i = h.finalize_fixed_reset();
            uniform_bytes.extend_from_slice(&b_i);
        }

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

    /// `ArkworksCompat` keeps the output of the arkworks 0.6
    /// `DefaultFieldHasher`, whose `Z_pad` is the element length and not the
    /// hash block size. When an arkworks release contains
    /// <https://github.com/arkworks-rs/algebra/pull/1140>, this test fails:
    /// compare `Rfc9380` with `DefaultFieldHasher` then.
    #[test]
    fn xmd_field_hasher_arkworks_compat_matches_arkworks() {
        use crate::suites::testing::TestSuite256;
        use ark_ff::field_hashers::DefaultFieldHasher;

        fn check<H, S, const SEC_PARAM: usize>()
        where
            H: digest::FixedOutputReset + digest::core_api::BlockSizeUser + Default + Clone,
            S: Suite,
        {
            let dst = [S::SUITE_ID, &[DomSep::HashToCurve as u8]].concat();
            let local =
                <XmdFieldHasher<H, S, ArkworksCompat> as HashToField<BaseField<S>>>::new(&dst);
            let arkworks =
                <DefaultFieldHasher<H, SEC_PARAM> as HashToField<BaseField<S>>>::new(&dst);
            for msg_len in [0, 1, 63, 64, 65, 127, 128, 129, 1000] {
                let msg = vec![0xa5; msg_len];
                let local: [BaseField<S>; 2] = local.hash_to_field(&msg);
                let arkworks: [BaseField<S>; 2] = arkworks.hash_to_field(&msg);
                assert_eq!(local, arkworks, "msg_len = {msg_len}");
            }
        }

        check::<sha2::Sha512, TestSuite, { TestSuite::SECURITY_PARAMETER }>();
        check::<sha2::Sha512, TestSuite256, { TestSuite256::SECURITY_PARAMETER }>();
        check::<sha2::Sha256, TestSuite, { TestSuite::SECURITY_PARAMETER }>();
    }

    fn rfc_field<F: ark_ff::PrimeField>(value: &serde_json::Value) -> F {
        let hex = value.as_str().unwrap().trim_start_matches("0x");
        F::from_be_bytes_mod_order(&hex::decode(hex).unwrap())
    }

    /// `Rfc9380` pads with the hash block size. P-256 with SHA-256 has a 48
    /// byte element and a 64 byte block, so a pad of the element length
    /// fails here. The test checks the `u` values of RFC 9380 Appendix J.1.1.
    ///
    /// The JSON file is `poc/vectors/P256_XMD:SHA-256_SSWU_RO_.json` of
    /// <https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve>, unchanged.
    #[test]
    fn xmd_field_hasher_rfc9380_matches_rfc_vectors() {
        use ark_secp256r1::Fq;

        let suite: serde_json::Value = serde_json::from_str(include_str!(
            "../../data/rfc9380/P256_XMD-SHA-256_SSWU_RO_.json"
        ))
        .unwrap();
        let dst = suite["dst"].as_str().unwrap().as_bytes();
        let hasher =
            <XmdFieldHasher<sha2::Sha256, TestSuite, Rfc9380> as HashToField<Fq>>::new(dst);
        for vector in suite["vectors"].as_array().unwrap() {
            let msg = vector["msg"].as_str().unwrap().as_bytes();
            let u: [Fq; 2] = hasher.hash_to_field(msg);
            let want = [rfc_field(&vector["u"][0]), rfc_field(&vector["u"][1])];
            assert_eq!(u, want, "msg length {}", msg.len());
        }
    }

    /// The Elligator2 suites take the map, the rational map and the cofactor
    /// clearing from arkworks, and RFC 9380 has no Bandersnatch vectors.
    /// edwards25519 has RFC vectors (Appendix J.5.1). Its suite maps on
    /// curve25519 and applies the RFC 7748 map, `x = sqrt(-486664) * s / t`,
    /// while arkworks always derives the Montgomery curve and the map from
    /// Appendix D.1. The test runs the arkworks code on the D.1 twisted
    /// Edwards form of curve25519, then scales `x` onto edwards25519.
    ///
    /// The JSON file is `poc/vectors/edwards25519_XMD:SHA-512_ELL2_RO_.json` of
    /// <https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve>, unchanged.
    #[test]
    fn ell2_xmd_matches_rfc_edwards25519_vectors() {
        use ark_curve25519::{Curve25519Config, Fq, Fr};
        use ark_ec::CurveConfig;
        use ark_ec::hashing::HashToCurve;
        use ark_ec::hashing::map_to_curve_hasher::{MapToCurve, MapToCurveBasedHasher};
        use ark_ec::twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig};
        use ark_ed25519::EdwardsAffine;
        use ark_ff::MontFp;

        #[derive(Clone, Default, PartialEq, Eq)]
        struct Curve25519Ell2;

        impl CurveConfig for Curve25519Ell2 {
            type BaseField = Fq;
            type ScalarField = Fr;
            const COFACTOR: &'static [u64] = Curve25519Config::COFACTOR;
            const COFACTOR_INV: Fr = Curve25519Config::COFACTOR_INV;
        }

        impl TECurveConfig for Curve25519Ell2 {
            const COEFF_A: Fq = <Curve25519Config as TECurveConfig>::COEFF_A;
            const COEFF_D: Fq = Curve25519Config::COEFF_D;
            const GENERATOR: Affine<Self> =
                Affine::new_unchecked(ark_curve25519::GENERATOR_X, ark_curve25519::GENERATOR_Y);
            type MontCurveConfig = Self;
        }

        impl MontCurveConfig for Curve25519Ell2 {
            const COEFF_A: Fq = <Curve25519Config as MontCurveConfig>::COEFF_A;
            const COEFF_B: Fq = Curve25519Config::COEFF_B;
            type TECurveConfig = Self;
        }

        impl Elligator2Config for Curve25519Ell2 {
            const Z: Fq = MontFp!("2");
            const ONE_OVER_COEFF_B_SQUARE: Fq = MontFp!("1");
            const COEFF_A_OVER_COEFF_B: Fq = MontFp!("486662");
        }

        // sqrt(-486664) with sgn0 = 0, as RFC 9380 Appendix G.2.2 requires.
        const C1: Fq =
            MontFp!("6853475219497561581579357271197624642482790079785650197046958215289687604742");
        let to_edwards25519 =
            |point: Affine<Curve25519Ell2>| EdwardsAffine::new_unchecked(C1 * point.x, point.y);

        type FieldHasher = XmdFieldHasher<sha2::Sha512, TestSuite, Rfc9380>;
        type Map = Elligator2Map<Curve25519Ell2>;
        let suite: serde_json::Value = serde_json::from_str(include_str!(
            "../../data/rfc9380/edwards25519_XMD-SHA-512_ELL2_RO_.json"
        ))
        .unwrap();
        let point = |value: &serde_json::Value| {
            EdwardsAffine::new_unchecked(rfc_field(&value["x"]), rfc_field(&value["y"]))
        };

        Map::check_parameters().unwrap();
        let dst = suite["dst"].as_str().unwrap().as_bytes();
        let field_hasher = <FieldHasher as HashToField<Fq>>::new(dst);
        let curve_hasher =
            MapToCurveBasedHasher::<Projective<Curve25519Ell2>, FieldHasher, Map>::new(dst)
                .unwrap();
        for vector in suite["vectors"].as_array().unwrap() {
            let msg = vector["msg"].as_str().unwrap().as_bytes();
            let u: [Fq; 2] = field_hasher.hash_to_field(msg);
            assert_eq!(u, [rfc_field(&vector["u"][0]), rfc_field(&vector["u"][1])]);
            let q0 = to_edwards25519(Map::map_to_curve(u[0]).unwrap());
            assert_eq!(q0, point(&vector["Q0"]), "Q0, msg length {}", msg.len());
            let q1 = to_edwards25519(Map::map_to_curve(u[1]).unwrap());
            assert_eq!(q1, point(&vector["Q1"]), "Q1, msg length {}", msg.len());
            let p = to_edwards25519(curve_hasher.hash(msg).unwrap());
            assert_eq!(p, point(&vector["P"]), "P, msg length {}", msg.len());
        }
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

        let narrow = hash_to_curve_ell2_xmd::<Narrow, sha2::Sha512>(b"data").unwrap();
        let wide = hash_to_curve_ell2_xmd::<Wide, sha2::Sha512>(b"data").unwrap();
        assert_ne!(narrow, wide);
        assert!(wide.is_on_curve() && wide.is_in_correct_subgroup_assuming_on_curve());

        type Xof = DigestXof<sha2::Sha512>;
        let narrow = hash_to_curve_ell2_xof::<Narrow, Xof>(b"data").unwrap();
        let wide = hash_to_curve_ell2_xof::<Wide, Xof>(b"data").unwrap();
        assert_ne!(narrow, wide);
        assert!(wide.is_on_curve() && wide.is_in_correct_subgroup_assuming_on_curve());
    }
}
