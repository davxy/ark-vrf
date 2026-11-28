#[macro_use]
mod bench_utils;

use ark_vrf::{
    Input, SecretKey,
    pedersen::{BatchItem, PedersenSuite, Proof},
};
use bench_utils::SuiteExt;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_pedersen_prove<S: PedersenSuite>(c: &mut Criterion) {
    let sk = SecretKey::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = sk.io_pair(input);

    let name = format!("{}/pedersen_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| Proof::prove(black_box(io), b"ad", &sk));
    });
}

fn bench_pedersen_verify<S: PedersenSuite>(c: &mut Criterion) {
    let sk = SecretKey::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = sk.io_pair(input);
    let (proof, _blinding) = Proof::prove(io, b"ad", &sk);

    let name = format!("{}/pedersen_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| black_box(&proof).verify(black_box(io), b"ad").unwrap());
    });
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

fn bench_pedersen_batch<S: PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::BatchVerifier;

    let sk = SecretKey::<S>::from_seed([0; 32]);
    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    let batch_items: Vec<_> = (0..max_batch_size)
        .map(|i| {
            let input = Input::<S>::new(format!("input-{i}").as_bytes()).unwrap();
            let io = sk.io_pair(input);
            let ad = format!("ad-{i}").into_bytes();
            let (proof, _) = Proof::prove(io, &ad, &sk);
            (io, ad, proof)
        })
        .collect();

    let prepare_group = format!("{}/pedersen_batch_prepare", S::SUITE_NAME);
    let verify_group = format!("{}/pedersen_batch_verify", S::SUITE_NAME);

    for &batch_size in BATCH_SIZES {
        let id = BenchmarkId::from_parameter(batch_size);

        c.benchmark_group(&prepare_group)
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .iter()
                        .map(|(io, ad, proof)| BatchItem::<S>::new(*io, ad, proof))
                        .collect();
                });
            });

        {
            let mut batch = BatchVerifier::<S>::new();
            for (io, ad, proof) in &batch_items[..batch_size] {
                batch.push(*io, ad, proof);
            }

            c.benchmark_group(&verify_group)
                .sample_size(10)
                .bench_function(id, |b| {
                    b.iter(|| batch.verify().unwrap());
                });
        }
    }
}

fn bench_pedersen_suite<S: PedersenSuite>(c: &mut Criterion) {
    bench_pedersen_prove::<S>(c);
    bench_pedersen_verify::<S>(c);
    bench_pedersen_batch::<S>(c);
}

fn bench_pedersen(c: &mut Criterion) {
    for_each_suite!(c, bench_pedersen_suite);
}

criterion_group!(benches, bench_pedersen);

criterion_main!(benches);
