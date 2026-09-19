#![allow(unused)]
#[cfg(not(feature = "std"))]
use ark_std::{vec, vec::Vec};

use crate::*;
use ark_std::{UniformRand, rand::RngCore};

pub const TEST_SEED: [u8; 32] = [0; 32];

// Points and scalars encoding utilities (little-endian, compressed).

/// Point encode.
pub fn point_encode<S: Suite>(pt: &AffinePoint<S>) -> Vec<u8> {
    let mut buf = Vec::new();
    pt.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Point decode.
pub fn point_decode<S: Suite>(buf: &[u8]) -> Result<AffinePoint<S>, Error> {
    AffinePoint::<S>::deserialize_compressed(buf).map_err(Into::into)
}

/// Scalar encode.
pub fn scalar_encode<S: Suite>(sc: &ScalarField<S>) -> Vec<u8> {
    let mut buf = Vec::new();
    sc.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Scalar decode.
pub fn scalar_decode<S: Suite>(buf: &[u8]) -> ScalarField<S> {
    ScalarField::<S>::from_le_bytes_mod_order(buf)
}

/// Zcash SRS file.
///
/// Derived from <https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony>.
/// Domain size: 2^11.
pub const BLS12_381_PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
);

/// Pure testing SRS file
///
/// Derived from seed `[0_u8; 32]`.
/// Domain size 2^9.
pub const BN254_PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/srs/bn254-testing-2-9-uncompressed.bin"
);

// Test vectors folder
pub const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/vectors");

/// Execute a closure and print its execution time.
pub fn timed<T, F: FnOnce() -> T>(desc: &str, f: F) -> T {
    let start = std::time::Instant::now();
    let result = f();
    println!("{}: {:?}", desc, start.elapsed());
    result
}

/// Generate a vector of random values.
pub fn random_vec<T: UniformRand>(n: usize, rng: Option<&mut dyn RngCore>) -> Vec<T> {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    (0..n).map(|_| T::rand(rng)).collect()
}

/// Generate a vector of random values.
pub fn random_val<T: UniformRand>(rng: Option<&mut dyn RngCore>) -> T {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    T::rand(rng)
}

pub trait CheckPoint {
    fn check(&self, in_prime_subgroup: bool) -> Result<(), &'static str>;
}

use ark_ec::short_weierstrass::{Affine as SWAffine, SWCurveConfig};
impl<C> CheckPoint for SWAffine<C>
where
    C: SWCurveConfig,
{
    fn check(&self, in_prime_subgroup: bool) -> Result<(), &'static str> {
        if !self.is_on_curve() {
            return Err("Point out of curve group");
        }
        if self.is_in_correct_subgroup_assuming_on_curve() != in_prime_subgroup {
            return Err("Point outside the expected curve subgroup");
        }
        Ok(())
    }
}

use ark_ec::twisted_edwards::{Affine as TEAffine, TECurveConfig};
impl<C> CheckPoint for TEAffine<C>
where
    C: TECurveConfig,
{
    fn check(&self, in_prime_subgroup: bool) -> Result<(), &'static str> {
        if !self.is_on_curve() {
            return Err("Point out of curve group");
        }
        if self.is_in_correct_subgroup_assuming_on_curve() != in_prime_subgroup {
            return Err("Point outside the expected curve subgroup");
        }
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestVectorMap(pub indexmap::IndexMap<String, String>);

impl TestVectorMap {
    pub fn get_bytes(&self, field: &str) -> Vec<u8> {
        hex::decode(self.0.get(field).unwrap()).unwrap()
    }

    pub fn set_bytes(&mut self, field: &str, buf: &[u8]) {
        self.0.insert(field.to_string(), hex::encode(buf));
    }

    pub fn get<T: CanonicalDeserialize>(&self, field: &str) -> T {
        let buf = self.get_bytes(field);
        T::deserialize_compressed(&buf[..]).unwrap()
    }

    pub fn set(&mut self, field: &str, value: &impl CanonicalSerialize) {
        let mut buf = Vec::new();
        value.serialize_compressed(&mut buf).unwrap();
        self.set_bytes(field, &buf);
    }
}

pub trait TestVectorTrait {
    fn name() -> String;

    fn new(comment: &str, seed: &[u8; 32], alpha: &[u8], ad: &[u8]) -> Self;

    fn from_map(map: &TestVectorMap) -> Self;

    fn to_map(&self) -> TestVectorMap;

    fn run(&self);
}

pub struct TestVector<S: Suite> {
    /// Useful info for the vector.
    pub comment: String,
    /// Secret key scalar.
    pub sk: ScalarField<S>,
    /// Public key point.
    pub pk: AffinePoint<S>,
    /// VRF input raw data.
    pub alpha: Vec<u8>,
    /// Signature additional raw data.
    pub ad: Vec<u8>,
    /// VRF input point.
    pub h: AffinePoint<S>,
    /// VRF output point.
    pub gamma: AffinePoint<S>,
    /// VRF output raw data
    pub beta: Vec<u8>,
}

impl<S: Suite> core::fmt::Debug for TestVector<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sk = hex::encode(scalar_encode::<S>(&self.sk));
        let pk = hex::encode(point_encode::<S>(&self.pk));
        let alpha = hex::encode(&self.alpha);
        let ad = hex::encode(&self.ad);
        let h = hex::encode(point_encode::<S>(&self.h));
        let gamma = hex::encode(point_encode::<S>(&self.gamma));
        let beta = hex::encode(&self.beta);
        f.debug_struct("TestVector")
            .field("comment", &self.comment)
            .field("sk", &sk)
            .field("pk", &pk)
            .field("alpha", &alpha)
            .field("ad", &ad)
            .field("h", &h)
            .field("gamma", &gamma)
            .field("beta", &beta)
            .finish()
    }
}

pub trait SuiteExt: Suite {
    const SUITE_NAME: &str;
}

impl<S: SuiteExt + std::fmt::Debug> TestVectorTrait for TestVector<S> {
    fn name() -> String {
        S::SUITE_NAME.to_string() + "_base"
    }

    fn new(comment: &str, seed: &[u8; 32], alpha: &[u8], ad: &[u8]) -> Self {
        let sk = Secret::<S>::from_seed(*seed);
        let pk = sk.public().0;

        let h = <S as Suite>::data_to_point(alpha).unwrap();
        let input = Input::from_affine_unchecked(h);

        let alpha = alpha.to_vec();
        let output = sk.output(input);
        let gamma = output.0;
        let beta = output.hash::<32>().to_vec();

        TestVector {
            comment: comment.to_string(),
            sk: sk.scalar,
            pk,
            alpha,
            ad: ad.to_vec(),
            h,
            gamma,
            beta,
        }
    }

    fn from_map(map: &TestVectorMap) -> Self {
        let item_bytes = |field| hex::decode(map.0.get(field).unwrap()).unwrap();
        let comment = map.0.get("comment").unwrap().to_string();
        let sk = scalar_decode::<S>(&item_bytes("sk"));
        let pk = point_decode::<S>(&item_bytes("pk")).unwrap();
        let alpha = item_bytes("alpha");
        let ad = item_bytes("ad");
        let h = point_decode::<S>(&item_bytes("h")).unwrap();
        let gamma = point_decode::<S>(&item_bytes("gamma")).unwrap();
        let beta = item_bytes("beta");
        Self {
            comment,
            sk,
            pk,
            alpha,
            ad,
            h,
            gamma,
            beta,
        }
    }

    fn to_map(&self) -> TestVectorMap {
        let items = [
            ("comment", self.comment.clone()),
            ("sk", hex::encode(scalar_encode::<S>(&self.sk))),
            ("pk", hex::encode(point_encode::<S>(&self.pk))),
            ("alpha", hex::encode(&self.alpha)),
            ("ad", hex::encode(&self.ad)),
            ("h", hex::encode(point_encode::<S>(&self.h))),
            ("gamma", hex::encode(point_encode::<S>(&self.gamma))),
            ("beta", hex::encode(&self.beta)),
        ];
        let map: indexmap::IndexMap<String, String> =
            items.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        TestVectorMap(map)
    }

    fn run(&self) {
        println!("Run test vector: {}", self.comment);

        let sk = Secret::<S>::from_scalar(self.sk);

        let pk = sk.public();
        assert_eq!(self.pk, pk.0, "public key ('pk') mismatch");

        let h = S::data_to_point(&self.alpha).unwrap();
        assert_eq!(self.h, h, "hash-to-curve ('h') mismatch");
        let input = Input::<S>::from_affine_unchecked(h);

        let output = sk.output(input);
        assert_eq!(self.gamma, output.0, "VRF pre-output ('gamma') mismatch");

        let beta = output.hash::<32>().to_vec();
        assert_eq!(self.beta, beta, "VRF output ('beta') mismatch");
    }
}

fn vector_filename(identifier: &str) -> String {
    [VECTORS_DIR, "/", identifier, ".json"].concat()
}

pub fn test_vectors_generate<V: TestVectorTrait + std::fmt::Debug>(identifier: &str) {
    use std::{fs::File, io::Write};

    // ("secret_seed", "vrf raw input", "additional data"))
    let var_data: Vec<(u8, &[u8], &[u8])> = vec![
        (1, b"", b""),
        (2, b"0a", b""),
        (3, b"", b"0b8c"),
        (4, b"73616D706C65", b""),
        (5, b"42616E646572736E6174636820766563746F72", b""),
        (5, b"42616E646572736E6174636820766563746F72", b"1F42"),
        (6, b"42616E646572736E6174636820766563746F72", b"1F42"),
    ];

    let mut vector_maps = Vec::with_capacity(var_data.len());

    for (i, var_data) in var_data.iter().enumerate() {
        let alpha = hex::decode(var_data.1).unwrap();
        let ad = hex::decode(var_data.2).unwrap();
        let comment = format!("{} - vector-{}", identifier, i + 1);
        let mut seed = [0u8; 32];
        seed[0] = var_data.0;
        let vector = V::new(&comment, &seed, &alpha, &ad);
        println!("Gen test vector: {}", comment);
        vector.run();
        vector_maps.push(vector.to_map());
    }

    let mut file = File::create(vector_filename(identifier)).unwrap();
    let json = serde_json::to_string_pretty(&vector_maps).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

pub fn test_vectors_process<V: TestVectorTrait>(identifier: &str) {
    use std::{fs::File, io::BufReader};

    let file = File::open(vector_filename(identifier)).unwrap();
    let reader = BufReader::new(file);

    let vector_maps: Vec<TestVectorMap> = serde_json::from_reader(reader).unwrap();

    for vector_map in vector_maps.iter() {
        let vector = V::from_map(vector_map);
        vector.run();
    }
}

#[macro_export]
macro_rules! test_vectors {
    ($vector_type:ty) => {
        #[allow(unused)]
        use $crate::testing::TestVectorTrait as _;
        $crate::test_vectors!($vector_type, &<$vector_type>::name());
    };
    ($vector_type:ty, $vector_name:expr) => {
        #[test]
        #[ignore = "test vectors generator"]
        fn vectors_generate() {
            $crate::testing::test_vectors_generate::<$vector_type>($vector_name);
        }

        #[test]
        fn vectors_process() {
            $crate::testing::test_vectors_process::<$vector_type>($vector_name);
        }
    };
}

/// A nonzero point outside the prime-order subgroup, `None` when the cofactor
/// is one.
pub trait TorsionPoint: Sized {
    fn torsion_point() -> Option<Self>;
}

/// `(0, -1)` has order two on every twisted Edwards curve. Other torsion
/// points may lie at infinity, where the affine conversion panics.
impl<C: TECurveConfig> TorsionPoint for TEAffine<C> {
    fn torsion_point() -> Option<Self> {
        use ark_ff::One;
        Some(Self::new_unchecked(
            C::BaseField::zero(),
            -C::BaseField::one(),
        ))
    }
}

/// Samples curve points from deterministic bytes and keeps the torsion
/// component `P - h^-1 * (h * P)` of the first sample outside the subgroup.
impl<C: SWCurveConfig> TorsionPoint for SWAffine<C> {
    fn torsion_point() -> Option<Self> {
        if C::cofactor_is_one() {
            return None;
        }
        let base_len = C::BaseField::default().serialized_size(ark_serialize::Compress::Yes);
        let mut rng = ark_std::test_rng();
        let mut bytes = vec![0u8; base_len];
        for _ in 0..1000 {
            rng.fill_bytes(&mut bytes);
            let Some(point) = Self::from_random_bytes(&bytes) else {
                continue;
            };
            let prime_order_part = point.mul_by_cofactor().mul_by_cofactor_inv();
            let torsion = (point.into_group() - prime_order_part.into_group()).into_affine();
            if !torsion.is_zero() {
                return Some(torsion);
            }
        }
        panic!("no torsion point found");
    }
}

/// Points outside the prime-order subgroup must not pass any checked path.
///
/// A key holder can add a torsion point `T` to the honest output `O`. The
/// verifiers accept `O + T` for about half of the additional data values,
/// while `O` and `O + T` hash to different VRF outputs. The checked
/// constructors and checked deserialization are the only barrier
/// (Cure53 PAR-03-010).
pub fn low_order_point_rejected<S: Suite>()
where
    AffinePoint<S>: TorsionPoint,
{
    let Some(torsion) = AffinePoint::<S>::torsion_point() else {
        return;
    };
    let secret = Secret::<S>::from_seed(TEST_SEED);
    let input = Input::<S>::new(b"low order").unwrap();
    let output = secret.output(input);

    assert_torsion_rejected(secret.public(), torsion);
    assert_torsion_rejected(input, torsion);
    let bad_output = assert_torsion_rejected(output, torsion);
    assert_ne!(output.hash::<32>(), bad_output.hash::<32>());
}

/// Checked paths reject `honest + torsion`; unchecked paths let it through.
fn assert_torsion_rejected<S: Suite, K: Sync>(
    honest: PointWrapper<S, K>,
    torsion: AffinePoint<S>,
) -> PointWrapper<S, K> {
    let bad = (honest.0 + torsion).into_affine();
    assert!(PointWrapper::<S, K>::from_affine(bad).is_err());
    let buf = point_encode::<S>(&bad);
    assert!(PointWrapper::<S, K>::deserialize_compressed(&buf[..]).is_err());
    let unchecked = PointWrapper::<S, K>::deserialize_compressed_unchecked(&buf[..]).unwrap();
    assert_eq!(unchecked.0, bad);
    unchecked
}

/// Flip every bit of `bytes` inside `component`, decode that component alone
/// with the plain arkworks decoder, and call a mutation that encodes back to
/// the original component an alias of the same value. `decode`, the checked
/// decoder of the whole byte string, must reject every alias. Returns the
/// aliases so the caller can assert that the check ran.
pub fn assert_aliases_rejected<T: CanonicalSerialize + CanonicalDeserialize>(
    bytes: &[u8],
    component: core::ops::Range<usize>,
    compress: ark_serialize::Compress,
    decode: impl Fn(&[u8]) -> bool,
) -> Vec<Vec<u8>> {
    let canonical = &bytes[component.clone()];
    let mut aliases = Vec::new();
    for bit in 0..canonical.len() * 8 {
        let mut mutated = bytes.to_vec();
        mutated[component.start + bit / 8] ^= 1 << (bit % 8);
        let plain = T::deserialize_with_mode(
            &mutated[component.clone()],
            compress,
            ark_serialize::Validate::No,
        );
        let Ok(value) = plain else {
            continue;
        };
        let mut reencoded = Vec::new();
        value.serialize_with_mode(&mut reencoded, compress).unwrap();
        if reencoded != canonical {
            continue;
        }
        assert!(
            !decode(&mutated),
            "alias accepted: bit {bit} of the component"
        );
        aliases.push(mutated);
    }
    aliases
}

/// Decode `bytes` as the single element of a `Vec<T>` with the checked
/// method. Arkworks decodes the elements of a sequence with `Validate::No`
/// and batch checks the values afterwards, so a rule that only the checked
/// decoder applies is skipped on this path.
pub fn decodes_inside_vec<T: CanonicalDeserialize>(
    bytes: &[u8],
    compress: ark_serialize::Compress,
) -> bool {
    let mut framed = Vec::new();
    1u64.serialize_with_mode(&mut framed, compress).unwrap();
    framed.extend_from_slice(bytes);
    Vec::<T>::deserialize_with_mode(&framed[..], compress, ark_serialize::Validate::Yes).is_ok()
}

/// A point must have one accepted encoding. Arkworks reads the identity from
/// several byte strings (any `x` with the infinity flag on Short Weierstrass
/// curves, either sign flag on Twisted Edwards curves) and ignores the sign
/// flag of an uncompressed Short Weierstrass point. Byte-keyed deduplication
/// and strong unforgeability of proofs need one encoding per value. The rule
/// does not depend on `Validate`: unchecked decoding skips the subgroup and
/// identity checks, not the encoding rule, so a value inside an arkworks
/// sequence, whose elements are decoded unchecked, gets one encoding too.
pub fn non_canonical_encoding_rejected<S: Suite>() {
    use crate::utils::canonical::{deserialize_canonical, deserialize_point};
    use ark_serialize::{Compress, Validate};

    let mut identity = Vec::new();
    AffinePoint::<S>::zero()
        .serialize_compressed(&mut identity)
        .unwrap();
    let checked = |bytes: &[u8]| deserialize_point::<S>(bytes, Compress::Yes, Validate::Yes);
    assert!(checked(&identity).unwrap().is_zero());
    // A stack buffer too small for the value spills to the heap.
    let spilled = |bytes: &[u8]| {
        deserialize_canonical::<AffinePoint<S>, 8>(bytes, Compress::Yes, Validate::Yes)
    };
    assert!(spilled(&identity).unwrap().is_zero());
    let aliases = assert_aliases_rejected::<AffinePoint<S>>(
        &identity,
        0..identity.len(),
        Compress::Yes,
        |bytes| checked(bytes).is_ok(),
    );
    assert!(!aliases.is_empty());
    for alias in &aliases {
        assert!(Public::<S>::deserialize_compressed_unchecked(&alias[..]).is_err());
        assert!(spilled(alias).is_err());
    }

    let point = Secret::<S>::from_seed(TEST_SEED).public().point();
    for compress in [Compress::Yes, Compress::No] {
        let mut bytes = Vec::new();
        point.serialize_with_mode(&mut bytes, compress).unwrap();
        let decode =
            |bytes: &[u8]| Public::<S>::deserialize_with_mode(bytes, compress, Validate::Yes);
        assert_eq!(decode(&bytes).unwrap().point(), point);
        assert_aliases_rejected::<AffinePoint<S>>(&bytes, 0..bytes.len(), compress, |bytes| {
            decode(bytes).is_ok() || decodes_inside_vec::<Public<S>>(bytes, compress)
        });
    }
}

/// The decoder reads one value and stops, as the `PointWrapper` and proof
/// docs state: values decode in sequence from one reader, and a trailing byte
/// is left unread, not rejected. Framing is the caller's job, so a consumer
/// must not key values by unframed bytes.
pub fn decoder_reads_one_value<S: Suite>() {
    let first = Secret::<S>::from_seed(TEST_SEED).public();
    let second = Secret::<S>::from_seed([1; 32]).public();
    let mut buf = Vec::new();
    first.serialize_compressed(&mut buf).unwrap();
    second.serialize_compressed(&mut buf).unwrap();
    buf.push(0xff);

    let mut reader = &buf[..];
    let decode = |reader: &mut &[u8]| Public::<S>::deserialize_compressed(reader).unwrap().point();
    assert_eq!(decode(&mut reader), first.point());
    assert_eq!(decode(&mut reader), second.point());
    assert_eq!(reader, &[0xff][..]);
}

#[macro_export]
macro_rules! suite_tests {
    ($suite:ty) => {
        #[test]
        fn low_order_point_rejected() {
            $crate::testing::low_order_point_rejected::<$suite>();
        }

        #[test]
        fn non_canonical_encoding_rejected() {
            $crate::testing::non_canonical_encoding_rejected::<$suite>();
        }

        #[test]
        fn decoder_reads_one_value() {
            $crate::testing::decoder_reads_one_value::<$suite>();
        }
    };
}
