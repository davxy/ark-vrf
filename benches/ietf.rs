#[macro_use]
mod bench_utils;

use ark_vrf::{Input, Secret};
use bench_utils::BenchInfo;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_ietf_prove<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::ietf::Prover;

    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let input = Input::<S>::new(b"bench input data").unwrap();
    let output = secret.output(input);

    let name = format!("{}/ietf_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.prove(black_box(input), black_box(output), b"ad"));
    });
}

fn bench_ietf_verify<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::ietf::{Prover, Verifier};

    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let public = secret.public();
    let input = Input::<S>::new(b"bench input data").unwrap();
    let output = secret.output(input);
    let proof = secret.prove(input, output, b"ad");

    let name = format!("{}/ietf_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            public
                .verify(
                    black_box(input),
                    black_box(output),
                    b"ad",
                    black_box(&proof),
                )
                .unwrap()
        });
    });
}

fn bench_ietf_suite<S: BenchInfo>(c: &mut Criterion) {
    S::print_info();
    bench_ietf_prove::<S>(c);
    bench_ietf_verify::<S>(c);
}

fn bench_ietf(c: &mut Criterion) {
    for_each_suite!(c, bench_ietf_suite);
}

criterion_group!(benches, bench_ietf);

criterion_main!(benches);
