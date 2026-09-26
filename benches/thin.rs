#[macro_use]
mod bench_utils;

use ark_std::UniformRand;
use ark_vrf::{AffinePoint, Input, Secret, Suite, thin::Proof};
use bench_utils::SuiteExt;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_thin_prove<S: Suite>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed([0; 32]);
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);

    let name = format!("{}/thin_prove", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| Proof::prove(black_box(io), b"ad", &secret));
    });
}

fn bench_thin_verify<S: Suite>(c: &mut Criterion) {
    let secret = Secret::<S>::from_seed([0; 32]);
    let public = secret.public();
    let input = Input::<S>::new(b"bench input data").unwrap();
    let io = secret.vrf_io(input);
    let proof = Proof::prove(io, b"ad", &secret);

    let name = format!("{}/thin_verify", S::SUITE_NAME);
    c.bench_function(&name, |b| {
        b.iter(|| {
            black_box(&proof)
                .verify(black_box(io), b"ad", &public)
                .unwrap()
        });
    });
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

fn bench_thin_batch<S: Suite>(c: &mut Criterion) {
    use ark_vrf::thin::{BatchItem, BatchVerifier};

    let secret = Secret::<S>::from_seed([0; 32]);
    let public = secret.public();
    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    let mut rng = ark_std::test_rng();
    let batch_items: Vec<_> = (0..max_batch_size)
        .map(|i| {
            let input = Input::<S>::from_affine_unchecked(AffinePoint::<S>::rand(&mut rng));
            let io = secret.vrf_io(input);
            let ad = format!("ad-{i}").into_bytes();
            let proof = Proof::prove(io, &ad, &secret);
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
                        .map(|(io, ad, proof)| BatchItem::<S>::new(*io, ad, proof, &public))
                        .collect();
                });
            });

        {
            let mut bv = BatchVerifier::<S>::new();
            for (io, ad, proof) in &batch_items[..batch_size] {
                bv.push(*io, ad, proof, &public);
            }

            c.benchmark_group(&verify_group)
                .sample_size(10)
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
                });
        }
    }
}

fn bench_thin_suite<S: Suite>(c: &mut Criterion) {
    bench_thin_prove::<S>(c);
    bench_thin_verify::<S>(c);
    bench_thin_batch::<S>(c);
}

fn bench_thin(c: &mut Criterion) {
    for_each_suite!(c, bench_thin_suite);
}

criterion_group!(benches, bench_thin);

criterion_main!(benches);
