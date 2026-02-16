#[macro_use]
mod bench_utils;

use ark_std::{rand::SeedableRng, UniformRand};
use ark_vrf::{AffinePoint, Input, Secret};
use bench_utils::BenchInfo;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_key_from_seed<S: BenchInfo>(c: &mut Criterion) {
    let name = format!("{}/key_from_seed", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| Secret::<S>::from_seed(black_box(b"bench secret seed")));
    });
}

fn bench_key_from_scalar<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let name = format!("{}/key_from_scalar", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| Secret::<S>::from_scalar(black_box(secret.scalar)));
    });
}

fn bench_vrf_output<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let input = Input::<S>::new(b"bench input data").unwrap();
    let name = format!("{}/vrf_output", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.output(black_box(input)));
    });
}

fn bench_data_to_point<S: BenchInfo>(c: &mut Criterion) {
    let name = format!("{}/data_to_point", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| S::data_to_point(black_box(b"bench input data")).unwrap());
    });
}

fn bench_challenge<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed(b"bench secret seed");
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
                b"ad",
            )
        });
    });
}

fn bench_point_to_hash<S: BenchInfo>(c: &mut Criterion) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let point = AffinePoint::<S>::rand(&mut rng);

    let name = format!("{}/point_to_hash", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| S::point_to_hash(black_box(&point)));
    });
}

fn bench_nonce<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let input = Input::<S>::new(b"bench input data").unwrap();

    let name = format!("{}/nonce[{}]", S::SUITE_NAME, S::NONCE_TAG);
    c.bench_function(&name, |b| {
        b.iter(|| S::nonce(black_box(&secret.scalar), black_box(input)));
    });
}

fn bench_point_encode<S: BenchInfo>(c: &mut Criterion) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let point = AffinePoint::<S>::rand(&mut rng);

    let name = format!("{}/point_encode", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| ark_vrf::codec::point_encode::<S>(black_box(&point)));
    });
}

fn bench_point_decode<S: BenchInfo>(c: &mut Criterion) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let point = AffinePoint::<S>::rand(&mut rng);
    let encoded = ark_vrf::codec::point_encode::<S>(&point);

    let name = format!("{}/point_decode", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| ark_vrf::codec::point_decode::<S>(black_box(&encoded)).unwrap());
    });
}

fn bench_scalar_encode<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed(b"bench secret seed");

    let name = format!("{}/scalar_encode", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| ark_vrf::codec::scalar_encode::<S>(black_box(&secret.scalar)));
    });
}

fn bench_scalar_decode<S: BenchInfo>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let encoded = ark_vrf::codec::scalar_encode::<S>(&secret.scalar);

    let name = format!("{}/scalar_decode", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| ark_vrf::codec::scalar_decode::<S>(black_box(&encoded)));
    });
}

// All common benchmarks for a single suite.
fn bench_common_suite<S: BenchInfo>(c: &mut Criterion) {
    S::print_info();
    bench_key_from_seed::<S>(c);
    bench_key_from_scalar::<S>(c);
    bench_vrf_output::<S>(c);
    bench_data_to_point::<S>(c);
    bench_challenge::<S>(c);
    bench_point_to_hash::<S>(c);
    bench_nonce::<S>(c);
    bench_point_encode::<S>(c);
    bench_point_decode::<S>(c);
    bench_scalar_encode::<S>(c);
    bench_scalar_decode::<S>(c);
}

fn bench_common(c: &mut Criterion) {
    // Per-suite benchmarks.
    for_each_suite!(c, bench_common_suite);
}

criterion_group!(benches, bench_common);

criterion_main!(benches);
