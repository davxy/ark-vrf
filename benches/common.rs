#![allow(dead_code, unused_imports, unused_variables)]

#[macro_use]
mod bench_utils;

use ark_std::UniformRand;
use ark_vrf::{AffinePoint, Input, Output, Secret, VrfIo};
use bench_utils::BenchInfo;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_vrf_output<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let name = format!("{}/vrf_output", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.output(black_box(input)));
    });
}

fn bench_data_to_point_tai<S: BenchInfo>(c: &mut Criterion) {
    let name = format!("{}/data_to_point_tai", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| ark_vrf::utils::hash_to_curve_tai::<S>(black_box(b"bench input data")).unwrap());
    });
}

fn bench_data_to_point_ell2<S: BenchInfo>(c: &mut Criterion)
where
    ark_vrf::CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    ark_vrf::CurveConfig<S>: ark_ec::hashing::curve_maps::elligator2::Elligator2Config,
    ark_ec::hashing::curve_maps::elligator2::Elligator2Map<ark_vrf::CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<
                <ark_vrf::AffinePoint<S> as ark_ec::AffineRepr>::Group,
            >,
{
    let h2c_suite_id = b"Bandersnatch_XMD:SHA-512_ELL2_RO_";
    let name = format!("{}/data_to_point_ell2", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            ark_vrf::utils::hash_to_curve_ell2_xmd::<S, sha2::Sha512>(
                black_box(b"bench input data"),
                h2c_suite_id,
            )
            .unwrap()
        });
    });
}

fn bench_challenge<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let output = secret.output(input);
    let generator = S::generator();

    let name = format!("{}/challenge", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            S::challenge(
                black_box(&[
                    &secret.public().0,
                    &input.0,
                    &output.0,
                    &generator,
                    &generator,
                ]),
                None,
            )
        });
    });
}

fn bench_point_to_hash<S: BenchInfo>(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let point = AffinePoint::<S>::rand(&mut rng);

    let name = format!("{}/point_to_hash", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| S::point_to_hash::<32>(black_box(&point)));
    });
}

fn bench_nonce<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();

    let name = format!("{}/nonce[{}]", S::SUITE_NAME, S::NONCE_TAG);
    c.bench_function(&name, |b| {
        b.iter(|| S::nonce(black_box(secret.scalar()), None));
    });
}

// All common benchmarks for a single suite.
fn bench_common_suite<S: BenchInfo>(c: &mut Criterion) {
    S::print_info();
    bench_vrf_output::<S>(c);
    bench_data_to_point_tai::<S>(c);
    bench_point_to_hash::<S>(c);
    bench_challenge::<S>(c);
    bench_nonce::<S>(c);
}

fn bench_common(c: &mut Criterion) {
    // Per-suite benchmarks.
    for_each_suite!(c, bench_common_suite);

    // ELL2 bench only for suites that support it.
    #[cfg(feature = "bandersnatch")]
    bench_data_to_point_ell2::<ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2>(c);
}

criterion_group!(benches, bench_common);

criterion_main!(benches);
