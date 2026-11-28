#[macro_use]
mod bench_utils;

use ark_vrf::{Input, SecretKey, Suite, tiny::Proof};
use bench_utils::SuiteExt;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_tiny_prove<S: Suite>(c: &mut Criterion) {
    let secret = SecretKey::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.io_pair(input);

    let name = format!("{}/tiny_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| Proof::prove(black_box(io), b"ad", &secret));
    });
}

fn bench_tiny_verify<S: Suite>(c: &mut Criterion) {
    let secret = SecretKey::<S>::from_seed([0; 32]);
    let pk = secret.public_key();
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.io_pair(input);
    let proof = Proof::prove(io, b"ad", &secret);

    let name = format!("{}/tiny_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| black_box(&proof).verify(black_box(io), b"ad", &pk).unwrap());
    });
}

fn bench_tiny_suite<S: Suite>(c: &mut Criterion) {
    bench_tiny_prove::<S>(c);
    bench_tiny_verify::<S>(c);
}

fn bench_tiny(c: &mut Criterion) {
    for_each_suite!(c, bench_tiny_suite);
}

criterion_group!(benches, bench_tiny);

criterion_main!(benches);
