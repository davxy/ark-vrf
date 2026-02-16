#[macro_use]
mod bench_utils;

use ark_std::{rand::SeedableRng, UniformRand};
use ark_vrf::{pedersen::PedersenSuite, AffinePoint, Input, Public, Secret};
use bench_utils::BenchInfo;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_pedersen_prove<S: BenchInfo + PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::Prover;

    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let input = Input::<S>::new(b"bench input data").unwrap();
    let output = secret.output(input);

    let name = format!("{}/pedersen_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| secret.prove(black_box(input), black_box(output), b"ad"));
    });
}

fn bench_pedersen_verify<S: BenchInfo + PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::{Prover, Verifier};

    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let input = Input::<S>::new(b"bench input data").unwrap();
    let output = secret.output(input);
    let (proof, _blinding) = secret.prove(input, output, b"ad");

    let name = format!("{}/pedersen_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            Public::<S>::verify(
                black_box(input),
                black_box(output),
                b"ad",
                black_box(&proof),
            )
            .unwrap()
        });
    });
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

fn bench_pedersen_batch<S: BenchInfo + PedersenSuite>(c: &mut Criterion) {
    use ark_vrf::pedersen::{BatchVerifier, Prover};

    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let batch_items: Vec<_> = (0..max_batch_size)
        .map(|i| {
            let input = Input::<S>::from(AffinePoint::<S>::rand(&mut rng));
            let output = secret.output(input);
            let ad = format!("ad-{i}").into_bytes();
            let (proof, _) = secret.prove(input, output, &ad);
            (input, output, ad, proof)
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
                        .map(|(input, output, ad, proof)| {
                            BatchVerifier::<S>::prepare(*input, *output, ad, proof)
                        })
                        .collect();
                });
            });

        {
            let mut bv = BatchVerifier::<S>::new();
            for (input, output, ad, proof) in &batch_items[..batch_size] {
                bv.push(*input, *output, ad, proof);
            }

            c.benchmark_group(&verify_group)
                .sample_size(10)
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
                });
        }
    }
}

fn bench_pedersen_suite<S: BenchInfo + PedersenSuite>(c: &mut Criterion) {
    bench_pedersen_prove::<S>(c);
    bench_pedersen_verify::<S>(c);
    bench_pedersen_batch::<S>(c);
}

fn bench_pedersen(c: &mut Criterion) {
    for_each_suite!(c, bench_pedersen_suite);
}

criterion_group!(benches, bench_pedersen);

criterion_main!(benches);
