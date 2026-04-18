#[macro_use]
mod bench_utils;

use ark_std::UniformRand;
use ark_vrf::{AffinePoint, Input, Secret, pedersen::PedersenSuite};
use bench_utils::SuiteExt;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_pedersen_prove<S: PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::Prover;

    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);

    let name = format!("{}/pedersen_prove", S::NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.prove(black_box(io), b"ad"));
    });
}

fn bench_pedersen_verify<S: PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::{Prover, Verifier};

    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);
    let (proof, _blinding) = secret.prove(io, b"ad");

    let name = format!("{}/pedersen_verify", S::NAME);
    c.bench_function(&name, |b| {
        b.iter(|| ark_vrf::Public::<S>::verify(black_box(io), b"ad", black_box(&proof)).unwrap());
    });
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

fn bench_pedersen_batch<S: PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::{BatchVerifier, Prover};

    let secret = Secret::<S>::from_seed([0; 32]);
    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    let mut rng = ark_std::test_rng();
    let batch_items: Vec<_> = (0..max_batch_size)
        .map(|i| {
            let input = Input::<S>::from_affine_unchecked(AffinePoint::<S>::rand(&mut rng));
            let io = secret.vrf_io(input);
            let ad = format!("ad-{i}").into_bytes();
            let (proof, _) = secret.prove(io, &ad);
            (io, ad, proof)
        })
        .collect();

    let prepare_group = format!("{}/pedersen_batch_prepare", S::NAME);
    let verify_group = format!("{}/pedersen_batch_verify", S::NAME);

    for &batch_size in BATCH_SIZES {
        let id = BenchmarkId::from_parameter(batch_size);

        c.benchmark_group(&prepare_group)
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .iter()
                        .map(|(io, ad, proof)| BatchVerifier::<S>::prepare(*io, ad, proof))
                        .collect();
                });
            });

        {
            let mut bv = BatchVerifier::<S>::new();
            for (io, ad, proof) in &batch_items[..batch_size] {
                bv.push(*io, ad, proof);
            }

            c.benchmark_group(&verify_group)
                .sample_size(10)
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
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
