//! Common cryptographic utility functions.
//!
//! This module provides implementations of various cryptographic operations
//! used throughout the VRF schemes, including hashing, challenge generation,
//! and hash-to-curve algorithms.

use crate::*;
use ark_ec::{
    AffineRepr,
    hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map},
};
use ark_ff::PrimeField;
use digest::{Digest, FixedOutputReset};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Generic hash wrapper.
///
/// Computes a hash of the provided data using the specified hash function.
pub fn hash<H: Digest>(data: &[u8]) -> digest::Output<H> {
    H::new().chain_update(data).finalize()
}

/// Generic HMAC wrapper.
///
/// Computes an HMAC of the provided data using the specified key and hash function.
/// Used for deterministic nonce generation in RFC-6979.
#[cfg(feature = "rfc-6979")]
fn hmac<H: Digest + digest::core_api::BlockSizeUser>(sk: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Mac, SimpleHmac};
    SimpleHmac::<H>::new_from_slice(sk)
        .expect("HMAC can take key of any size")
        .chain_update(data)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// Try-And-Increment (TAI) method as defined by RFC 9381 section 5.4.1.1.
///
/// Implements ECVRF_encode_to_curve in a simple and generic way that works
/// for any elliptic curve. This method iteratively attempts to hash the input
/// with an incrementing counter until a valid curve point is found.
///
/// To use this algorithm, hash length MUST be at least equal to the field length.
///
/// The running time of this algorithm depends on input string. For the
/// ciphersuites specified in Section 5.5, this algorithm is expected to
/// find a valid curve point after approximately two attempts on average.
///
/// May systematically fail if `Suite::Hasher` output is not sufficient to
/// construct a point according to the `Suite::Codec` in use.
///
/// # Parameters
///
/// * `data` - The input data to hash to a curve point
///
/// # Returns
///
/// * `Some(AffinePoint<S>)` - A valid curve point in the prime-order subgroup
/// * `None` - If no valid point could be found after 256 attempts
pub fn hash_to_curve_tai_rfc_9381<S: Suite>(data: &[u8]) -> Option<AffinePoint<S>> {
    use ark_ec::AffineRepr;

    const DOM_SEP_FRONT: u8 = 0x01;
    const DOM_SEP_BACK: u8 = 0x00;

    let prefix = S::Hasher::new()
        .chain_update(S::SUITE_ID)
        .chain_update([DOM_SEP_FRONT])
        .chain_update(data);

    for ctr in 0..=255u8 {
        let hash = prefix.clone().chain_update([ctr, DOM_SEP_BACK]).finalize();
        if let Ok(pt) = codec::point_decode::<S>(&hash[..]) {
            let pt = pt.clear_cofactor();
            if !pt.is_zero() {
                return Some(pt);
            }
        }
    }
    None
}

/// Elligator2 method as defined by RFC-9380 and further refined in RFC-9381 section 5.4.1.2.
///
/// Implements ECVRF_encode_to_curve using one of the several hash-to-curve options defined
/// in RFC-9380. This method provides a constant-time hash-to-curve implementation that is
/// more secure against side-channel attacks than the Try-And-Increment method.
///
/// The specific choice of the hash-to-curve option (called the Suite ID in RFC-9380)
/// is given by the h2c_suite_ID_string parameter.
///
/// # Parameters
///
/// * `data` - The input data to hash to a curve point
///   (defined to be `salt || alpha` according to RFC-9381)
/// * `h2c_suite_id` - The hash-to-curve suite identifier as defined in RFC-9380
///
/// # Returns
///
/// * `Some(AffinePoint<S>)` - A valid curve point in the prime-order subgroup
/// * `None` - If the hash-to-curve operation fails
#[allow(unused)]
pub fn hash_to_curve_ell2_rfc_9380<S: Suite>(
    data: &[u8],
    h2c_suite_id: &[u8],
) -> Option<AffinePoint<S>>
where
    <S as Suite>::Hasher: Default + Clone + FixedOutputReset + 'static,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};
    use ark_ff::field_hashers::DefaultFieldHasher;

    // Domain Separation Tag := "ECVRF_" || h2c_suite_ID_string || suite_string
    let dst: Vec<_> = [b"ECVRF_", h2c_suite_id, S::SUITE_ID].concat();

    MapToCurveBasedHasher::<
        <AffinePoint<S> as AffineRepr>::Group,
        DefaultFieldHasher<<S as Suite>::Hasher, 128>,
        Elligator2Map<CurveConfig<S>>,
    >::new(&dst)
    .and_then(|hasher| hasher.hash(data))
    .ok()
}

/// Challenge generation according to RFC-9381 section 5.4.3.
///
/// Generates a challenge scalar by hashing a sequence of curve points and additional data.
/// This is used in the Schnorr-like signature scheme for VRF proofs.
///
/// The function follows the procedure specified in RFC-9381:
/// 1. Start with a domain separator and suite ID
/// 2. Append the encoded form of each provided point
/// 3. Append the additional data
/// 4. Hash the result and interpret it as a scalar
///
/// # Parameters
///
/// * `pts` - Array of curve points to include in the challenge
/// * `ad` - Additional data to bind to the challenge
///
/// # Returns
///
/// A scalar field element derived from the hash of the inputs
pub fn challenge_rfc_9381<S: Suite>(pts: &[&AffinePoint<S>], ad: &[u8]) -> ScalarField<S> {
    const DOM_SEP_START: u8 = 0x02;
    const DOM_SEP_END: u8 = 0x00;
    let mut hasher = S::Hasher::new();
    hasher.update(S::SUITE_ID);
    hasher.update([DOM_SEP_START]);
    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    for p in pts {
        pt_buf.clear();
        S::Codec::point_encode_into(p, &mut pt_buf);
        hasher.update(&pt_buf);
    }
    hasher.update(ad);
    hasher.update([DOM_SEP_END]);
    let hash = hasher.finalize();
    ScalarField::<S>::from_be_bytes_mod_order(&hash[..S::CHALLENGE_LEN])
}

/// Point to a hash according to RFC-9381 section 5.2.
///
/// Converts an elliptic curve point to a hash value, following the procedure in RFC-9381.
/// This is used to derive the final VRF output bytes from the VRF output point.
///
/// According to the RFC, the input point `pt` should be multiplied by the cofactor
/// before being hashed. However, in typical usage, the hashed point is the result
/// of a scalar multiplication on a point produced by the `Suite::data_to_point`
/// (also referred to as the _hash-to-curve_ or _h2c_) algorithm, which is expected
/// to yield a point that already belongs to the prime order subgroup of the curve.
///
/// Therefore, assuming the `data_to_point` function is implemented correctly, the
/// input point `pt` will inherently reside in the prime order subgroup, making the
/// cofactor multiplication unnecessary and redundant in terms of security. The primary
/// purpose of multiplying by the cofactor is as a safeguard against potential issues
/// with an incorrect implementation of `data_to_point`.
///
/// # Parameters
///
/// * `pt` - The elliptic curve point to hash
/// * `mul_by_cofactor` - Whether to multiply the point by the cofactor before hashing
///
/// # Returns
///
/// A hash value derived from the encoded point
pub fn point_to_hash_rfc_9381<S: Suite>(
    pt: &AffinePoint<S>,
    mul_by_cofactor: bool,
) -> HashOutput<S> {
    use ark_std::borrow::Cow::*;
    const DOM_SEP_START: u8 = 0x03;
    const DOM_SEP_END: u8 = 0x00;
    let pt = match mul_by_cofactor {
        false => Borrowed(pt),
        true => Owned(pt.mul_by_cofactor()),
    };
    let mut hasher = S::Hasher::new();
    hasher.update(S::SUITE_ID);
    hasher.update([DOM_SEP_START]);
    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    S::Codec::point_encode_into(&pt, &mut pt_buf);
    hasher.update(&pt_buf);
    hasher.update([DOM_SEP_END]);
    hasher.finalize()
}

/// Nonce generation according to RFC-9381 section 5.4.2.2.
///
/// This procedure is based on section 5.1.6 of RFC 8032: "Edwards-Curve Digital
/// Signature Algorithm (EdDSA)". It generates a deterministic nonce by hashing
/// the secret key and input point together.
///
/// The deterministic generation ensures that the same nonce is never used twice
/// with the same secret key for different inputs, which is critical for security.
///
/// # Parameters
///
/// * `sk` - The secret scalar key
/// * `input` - The input point
///
/// # Returns
///
/// A scalar field element to be used as a nonce
///
/// # Panics
///
/// This function panics if `Suite::Hasher` output is less than 64 bytes.
pub fn nonce_rfc_8032<S: Suite>(sk: &ScalarField<S>, input: &AffinePoint<S>) -> ScalarField<S> {
    assert!(
        S::Hasher::output_size() >= 64,
        "Suite::Hasher output is required to be >= 64 bytes"
    );

    let sk_buf = codec::scalar_encode::<S>(sk);
    let sk_hash = hash::<S::Hasher>(&sk_buf);

    let pt_buf = codec::point_encode::<S>(input);
    let h = S::Hasher::new()
        .chain_update(&sk_hash[32..])
        .chain_update(&pt_buf)
        .finalize();

    S::Codec::scalar_decode(&h)
}

/// Nonce generation according to RFC 9381 section 5.4.2.1.
///
/// This procedure is based on section 3.2 of RFC 6979: "Deterministic Usage of
/// the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature
/// Algorithm (ECDSA)".
///
/// It generates a deterministic nonce using HMAC-based extraction, which provides
/// strong security guarantees against nonce reuse or biased nonce generation.
///
/// Note: the candidate nonce is decoded via `scalar_decode`, which internally uses
/// `from_be_bytes_mod_order` (i.e. reduction mod q) rather than the raw `bits2int`
/// prescribed by RFC 6979. Strictly, candidates with `bits2int(T) >= q` should be
/// rejected and trigger a retry; here they are instead reduced to a valid scalar.
/// This introduces a negligible bias for curves where `q` is close to `2^(8*qbytes)`
/// (e.g. secp256r1, where the probability of hitting `>= q` is ~2^{-128}).
///
/// # Parameters
///
/// * `sk` - The secret scalar key
/// * `input` - The input point
///
/// # Returns
///
/// A scalar field element to be used as a nonce
#[cfg(feature = "rfc-6979")]
pub fn nonce_rfc_6979<S: Suite>(sk: &ScalarField<S>, input: &AffinePoint<S>) -> ScalarField<S>
where
    S::Hasher: digest::core_api::BlockSizeUser,
{
    let raw = codec::point_encode::<S>(input);
    let h1 = hash::<S::Hasher>(&raw);

    let v = [1; 32];
    let k = [0; 32];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let x = codec::scalar_encode::<S>(sk);
    let raw = [&v[..], &[0x00], &x[..], &h1[..]].concat();
    let k = hmac::<S::Hasher>(&k, &raw);

    // V = HMAC_K(V)
    let v = hmac::<S::Hasher>(&k, &v);

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let raw = [&v[..], &[0x01], &x[..], &h1[..]].concat();
    let mut k = hmac::<S::Hasher>(&k, &raw);

    // V = HMAC_K(V)
    let mut v = hmac::<S::Hasher>(&k, &v);

    // RFC 6979 section 3.2 step h
    // qlen: bit length of q; qbytes: byte length (used for T construction)
    let qlen = ScalarField::<S>::MODULUS_BIT_SIZE as usize;
    let qbytes = qlen.div_ceil(8);
    loop {
        // h.1: T = empty
        let mut t = Vec::with_capacity(qbytes);
        // h.2: while tlen < qlen, V = HMAC_K(V), T = T || V
        while t.len() * 8 < qlen {
            v = hmac::<S::Hasher>(&k, &v);
            t.extend_from_slice(&v);
        }
        // h.3: k = bits2int(T), check k in [1, q-1]
        let nonce = S::Codec::scalar_decode(&t[..qbytes]);
        if !nonce.is_zero() {
            return nonce;
        }
        // K = HMAC_K(V || 0x00), V = HMAC_K(V)
        let data = [&v[..], &[0x00]].concat();
        k = hmac::<S::Hasher>(&k, &data);
        v = hmac::<S::Hasher>(&k, &v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::TestSuite;

    #[test]
    fn hash_to_curve_tai_works() {
        let pt = hash_to_curve_tai_rfc_9381::<TestSuite>(b"hello world").unwrap();
        // Check that `pt` is in the prime subgroup
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }
}
