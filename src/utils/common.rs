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
use core::iter::Chain;
use digest::{Digest, FixedOutputReset};

/// Wrapper around [`Chain`] that implements [`ExactSizeIterator`].
///
/// Safe because the constituent iterators are both `ExactSizeIterator`
/// with small lengths (VRF I/O pairs), so overflow is not a concern.
#[derive(Clone)]
pub struct ExactChain<A, B>(Chain<A, B>, usize);

impl<A, B> ExactChain<A, B>
where
    A: ExactSizeIterator,
    B: ExactSizeIterator<Item = A::Item>,
{
    pub fn new(a: A, b: B) -> Self {
        let len = a.len() + b.len();
        Self(a.chain(b), len)
    }
}

impl<A, B> Iterator for ExactChain<A, B>
where
    A: Iterator,
    B: Iterator<Item = A::Item>,
{
    type Item = A::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next();
        if item.is_some() {
            self.1 -= 1;
        }
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.1, Some(self.1))
    }
}

impl<A, B> ExactSizeIterator for ExactChain<A, B>
where
    A: Iterator,
    B: Iterator<Item = A::Item>,
{
}

/// Internal domain separation tags for protocol hashing.
#[repr(u8)]
pub(crate) enum DomSep {
    HashToCurveTai = 0x01,
    Challenge = 0x02,
    PointToHash = 0x03,
    Delinearize = 0x04,
    PedersenBlinding = 0xCC,
    End = 0x00,
}

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

    let prefix = S::Hasher::new()
        .chain_update(S::SUITE_ID)
        .chain_update([DomSep::HashToCurveTai as u8])
        .chain_update(data);

    for ctr in 0..=255u8 {
        let hash = prefix
            .clone()
            .chain_update([ctr, DomSep::End as u8])
            .finalize();
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
    let mut hasher = S::Hasher::new();
    hasher.update(S::SUITE_ID);
    hasher.update([DomSep::Challenge as u8]);
    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    for p in pts {
        pt_buf.clear();
        S::Codec::point_encode_into(p, &mut pt_buf);
        hasher.update(&pt_buf);
    }
    hasher.update(ad);
    hasher.update([DomSep::End as u8]);
    let hash = hasher.finalize();
    codec::scalar_decode::<S>(&hash[..S::CHALLENGE_LEN])
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
    let pt = match mul_by_cofactor {
        false => Borrowed(pt),
        true => Owned(pt.mul_by_cofactor()),
    };
    let mut hasher = S::Hasher::new();
    hasher.update(S::SUITE_ID);
    hasher.update([DomSep::PointToHash as u8]);
    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    S::Codec::point_encode_into(&pt, &mut pt_buf);
    hasher.update(&pt_buf);
    hasher.update([DomSep::End as u8]);
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
/// The `ad` (additional data) is mixed into the hash to ensure distinct nonces
/// when the same secret key and input are used with different auxiliary data.
///
/// # Parameters
///
/// * `sk` - The secret scalar key
/// * `pts` - Points to bind into the nonce derivation
/// * `ad` - Additional data bound to the proof
///
/// # Returns
///
/// A scalar field element to be used as a nonce
///
/// # Panics
///
/// This function panics if `Suite::Hasher` output is less than 64 bytes.
pub fn nonce_rfc_8032<S: Suite>(
    sk: &ScalarField<S>,
    pts: &[&AffinePoint<S>],
    ad: &[u8],
) -> ScalarField<S> {
    assert!(
        S::Hasher::output_size() >= 64,
        "Suite::Hasher output is required to be >= 64 bytes"
    );

    let sk_buf = codec::scalar_encode::<S>(sk);
    let sk_hash = hash::<S::Hasher>(&sk_buf);

    let mut hasher = S::Hasher::new();
    hasher.update(&sk_hash[32..]);
    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    for pt in pts {
        pt_buf.clear();
        S::Codec::point_encode_into(pt, &mut pt_buf);
        hasher.update(&pt_buf);
    }
    hasher.update(ad);
    let h = hasher.finalize();

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
/// The `ad` (additional data) is mixed into the initial hash to ensure distinct
/// nonces when the same secret key and input are used with different auxiliary data.
///
/// Note: the candidate nonce is decoded via `scalar_decode`, which internally uses
/// `from_(le/be)_bytes_mod_order` (i.e. reduction mod q) rather than the raw `bits2int`
/// prescribed by RFC 6979. Strictly, candidates with `bits2int(T) >= q` should be
/// rejected and trigger a retry; here they are instead reduced to a valid scalar.
/// This introduces a negligible bias for curves where `q` is close to `2^(8*qbytes)`
/// (e.g. secp256r1, where the probability of hitting `>= q` is ~2^{-128}).
///
/// # Parameters
///
/// * `sk` - The secret scalar key
/// * `pts` - Points to bind into the nonce derivation
/// * `ad` - Additional data bound to the proof
///
/// # Returns
///
/// A scalar field element to be used as a nonce
#[cfg(feature = "rfc-6979")]
pub fn nonce_rfc_6979<S: Suite>(
    sk: &ScalarField<S>,
    pts: &[&AffinePoint<S>],
    ad: &[u8],
) -> ScalarField<S>
where
    S::Hasher: digest::core_api::BlockSizeUser,
{
    let mut h1_hasher = S::Hasher::new();
    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    for pt in pts {
        pt_buf.clear();
        S::Codec::point_encode_into(pt, &mut pt_buf);
        h1_hasher.update(&pt_buf);
    }
    h1_hasher.update(ad);
    let h1 = h1_hasher.finalize();

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

/// Stateful stream of 128-bit delinearization scalars backed by a seeded
/// ChaCha20 PRNG. Created by [`delinearize_scalars`].
pub(crate) struct DelinearizeScalars<S: Suite> {
    rng: rand_chacha::ChaCha20Rng,
    _marker: core::marker::PhantomData<S>,
}

impl<S: Suite> DelinearizeScalars<S> {
    /// Draw the next 128-bit scalar.
    pub fn next(&mut self) -> ScalarField<S> {
        use ark_std::rand::RngCore;
        let mut buf = [0u8; 16];
        self.rng.fill_bytes(&mut buf);
        S::Codec::scalar_decode(&buf)
    }

    /// Collect `n` scalars into a `Vec`.
    pub fn take_vec(&mut self, n: usize) -> Vec<ScalarField<S>> {
        (0..n).map(|_| self.next()).collect()
    }
}

/// Seed a [`DelinearizeScalars`] stream from an iterator of [`VrfIo`] pairs
/// and auxiliary data. The seed is derived deterministically by hashing all
/// encoded points together with `ad`.
pub(crate) fn delinearize_scalars<S: Suite>(
    iter: impl ExactSizeIterator<Item = VrfIo<S>>,
    ad: &[u8],
) -> DelinearizeScalars<S> {
    use ark_std::rand::SeedableRng;

    let n = u32::try_from(iter.len()).expect("too many input-output pairs");

    // Seed: H(suite_id || dom_sep || N || encode(H_0) || encode(Gamma_0) || ... || ad || 0x00)
    let mut hasher = S::Hasher::new();
    hasher.update(S::SUITE_ID);
    hasher.update([DomSep::Delinearize as u8]);
    hasher.update(n.to_le_bytes());

    let mut pt_buf = Vec::with_capacity(S::Codec::POINT_ENCODED_LEN);
    for io in iter {
        pt_buf.clear();
        S::Codec::point_encode_into(&io.input.0, &mut pt_buf);
        hasher.update(&pt_buf);
        pt_buf.clear();
        S::Codec::point_encode_into(&io.output.0, &mut pt_buf);
        hasher.update(&pt_buf);
    }
    hasher.update(ad);
    hasher.update([DomSep::End as u8]);
    let seed = hasher.finalize();

    assert!(seed.len() >= 32, "hash output too short for ChaCha20 seed");
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&seed[..32]);

    DelinearizeScalars {
        rng: rand_chacha::ChaCha20Rng::from_seed(rng_seed),
        _marker: core::marker::PhantomData,
    }
}

/// Delinearize multiple input-output pairs into a single pair.
///
/// Derives 128-bit delinearization scalars (Privacy Pass / dleq_vrf technique)
/// and folds the ios into `(sum(z_i * input_i), sum(z_i * output_i))`.
/// The resulting `(Input, Output)` can be passed directly to a scheme's
/// `prove` / `verify` to obtain or check a single proof covering all pairs.
///
/// The ordering of items matters: the delinearization scalars are derived from
/// the hash of the pairs in the given order, so the prover and verifier must
/// use the same ordering to obtain the same merged pair.
///
/// - N=0: returns the identity point for both input and output.
/// - N=1: returns the pair as-is, no hashing or scalar multiplications.
/// - N>1: derives per-pair 128-bit scalars (2^{-128} Schwartz-Zippel soundness)
///   and returns their linear combination.
///
/// The iterator must be `ExactSizeIterator` (to know N) and `Clone` (for the
/// two-pass hash-then-fold without allocation).
///
/// # WARNING: N=0
///
/// When the iterator is empty, both returned points are the identity (zero point).
/// Since `sk * 0 = 0` for every secret key, the resulting DLEQ proof degenerates
/// into a Schnorr signature over the additional data -- it binds the public key
/// to `ad` but provides **no VRF output**. The `Output` is a public constant
/// (the identity point) and **must not** be used to derive VRF randomness.
/// Doing so would produce a predictable, key-independent value.
pub fn delinearize<S: Suite>(
    iter: impl ExactSizeIterator<Item = VrfIo<S>> + Clone,
    ad: &[u8],
) -> (Input<S>, Output<S>) {
    let zero = AffinePoint::<S>::zero();
    let n = iter.len();

    if n == 0 {
        return (Input(zero), Output(zero));
    }

    if n == 1 {
        let io = iter.clone().next().unwrap();
        return (io.input, io.output);
    }

    // MSM has bucket-setup overhead that dominates for small N.
    // Fold is faster below this threshold; MSM wins above it.
    const MSM_THRESHOLD: usize = 16;

    let mut scalars = delinearize_scalars(iter.clone(), ad);

    let zero = zero.into_group();
    let (input, output) = if n < MSM_THRESHOLD {
        iter.fold((zero, zero), |(h_acc, g_acc), io| {
            let z = scalars.next();
            (h_acc + io.input.0 * z, g_acc + io.output.0 * z)
        })
    } else {
        let scalars = scalars.take_vec(n);
        let (inputs, outputs): (Vec<_>, Vec<_>) = iter.map(|io| (io.input.0, io.output.0)).unzip();
        use ark_ec::VariableBaseMSM;
        type Group<S> = <AffinePoint<S> as AffineRepr>::Group;
        let input = Group::<S>::msm_unchecked(&inputs, &scalars);
        let output = Group::<S>::msm_unchecked(&outputs, &scalars);
        (input, output)
    };
    let norms = CurveGroup::normalize_batch(&[input, output]);
    (Input(norms[0]), Output(norms[1]))
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
