#[macro_use]
mod bench_utils;

use ark_std::UniformRand;
use ark_vrf::{AffinePoint, Input, Secret};
use bench_utils::BenchInfo;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_thin_prove<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::thin::Prover;

    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);

    let name = format!("{}/thin_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.prove(black_box(io), b"ad"));
    });
}

fn bench_thin_verify<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::thin::{Prover, Verifier};

    let secret = Secret::<S>::from_seed([0; 32]);
    let public = secret.public();
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);
    let proof = secret.prove(io, b"ad");

    let name = format!("{}/thin_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            public
                .verify(black_box(io), b"ad", black_box(&proof))
                .unwrap()
        });
    });
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

fn bench_thin_batch<S: BenchInfo>(c: &mut Criterion) {
    use ark_vrf::thin::{BatchVerifier, Prover};

    let secret = Secret::<S>::from_seed([0; 32]);
    let public = secret.public();
    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    let mut rng = ark_std::test_rng();
    let batch_items: Vec<_> = (0..max_batch_size)
        .map(|i| {
            let input = Input::<S>::from_affine(AffinePoint::<S>::rand(&mut rng));
            let io = secret.vrf_io(input);
            let ad = format!("ad-{i}").into_bytes();
            let proof = secret.prove(io, &ad);
            (io, ad, proof)
        })
        .collect();

    let prepare_group = format!("{}/thin_batch_prepare", S::SUITE_NAME);
    let verify_group = format!("{}/thin_batch_verify", S::SUITE_NAME);

    for &batch_size in BATCH_SIZES {
        let id = BenchmarkId::from_parameter(batch_size);

        c.benchmark_group(&prepare_group)
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .iter()
                        .map(|(io, ad, proof)| BatchVerifier::<S>::prepare(&public, *io, ad, proof))
                        .collect();
                });
            });

        {
            let mut bv = BatchVerifier::<S>::new();
            for (io, ad, proof) in &batch_items[..batch_size] {
                bv.push(&public, *io, ad, proof);
            }

            c.benchmark_group(&verify_group)
                .sample_size(10)
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
                });
        }
    }
}

fn bench_thin_suite<S: BenchInfo>(c: &mut Criterion) {
    bench_thin_prove::<S>(c);
    bench_thin_verify::<S>(c);
    bench_thin_batch::<S>(c);
}

fn bench_thin(c: &mut Criterion) {
    for_each_suite!(c, bench_thin_suite);
}

criterion_group!(benches, bench_thin);

criterion_main!(benches);
