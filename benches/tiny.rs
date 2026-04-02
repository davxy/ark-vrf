#[macro_use]
mod bench_utils;

use ark_vrf::{Input, Secret};
use bench_utils::BenchInfo;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_tiny_prove<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::tiny::Prover;

    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);

    let name = format!("{}/tiny_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.prove(black_box(io), b"ad"));
    });
}

fn bench_tiny_verify<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::tiny::{Prover, Verifier};

    let secret = Secret::<S>::from_seed([0; 32]);
    let public = secret.public();
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);
    let proof = secret.prove(io, b"ad");

    let name = format!("{}/tiny_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            public
                .verify(black_box(io), b"ad", black_box(&proof))
                .unwrap()
        });
    });
}

fn bench_tiny_suite<S: BenchInfo>(c: &mut Criterion) {
    S::print_info();
    bench_tiny_prove::<S>(c);
    bench_tiny_verify::<S>(c);
}

fn bench_tiny(c: &mut Criterion) {
    for_each_suite!(c, bench_tiny_suite);
}

criterion_group!(benches, bench_tiny);

criterion_main!(benches);
