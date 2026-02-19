#[macro_use]
mod bench_utils;

use ark_std::{UniformRand, rand::SeedableRng};
use ark_vrf::{
    AffinePoint, Input, Output, Secret,
    ring::{self, BatchVerifier, Prover, RingSuite, Verifier},
};
use bench_utils::BenchInfo;
use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rayon::prelude::*;

const RING_SIZES: [usize; 3] = [255, 1023, 2047];

struct RingSetup<S: RingSuite> {
    secret: Secret<S>,
    input: Input<S>,
    output: Output<S>,
    ring: Vec<AffinePoint<S>>,
    prover_idx: usize,
    params: ring::RingProofParams<S>,
}

fn make_ring_setup<S: RingSuite>(ring_size: usize) -> RingSetup<S> {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let secret = Secret::<S>::from_seed(b"bench secret seed");
    let public = secret.public();
    let input = Input::<S>::new(b"bench input data").unwrap();
    let output = secret.output(input);

    let prover_idx = 3;
    let mut ring: Vec<AffinePoint<S>> = (0..ring_size)
        .map(|_| AffinePoint::<S>::rand(&mut rng))
        .collect();
    ring[prover_idx] = public.0;

    let params = ring::RingProofParams::<S>::from_rand(ring_size, &mut rng);

    RingSetup {
        secret,
        input,
        output,
        ring,
        prover_idx,
        params,
    }
}

fn ring_benches<S: BenchInfo + RingSuite>(c: &mut Criterion) {
    for &n in &RING_SIZES {
        let setup = make_ring_setup::<S>(n);
        let id = BenchmarkId::from_parameter(n);

        c.benchmark_group(format!("{}/ring_params_setup", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    ring::RingProofParams::<S>::from_pcs_params(
                        black_box(n),
                        setup.params.pcs.clone(),
                    )
                    .unwrap()
                });
            });

        c.benchmark_group(format!("{}/ring_prover_key", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.prover_key(black_box(&setup.ring)));
            });

        c.benchmark_group(format!("{}/ring_verifier_key", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.verifier_key(black_box(&setup.ring)));
            });

        let prover_key = setup.params.prover_key(&setup.ring);
        let prover = setup.params.prover(prover_key, setup.prover_idx);

        c.benchmark_group(format!("{}/ring_prove", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    setup
                        .secret
                        .prove(setup.input, setup.output, b"ad", black_box(&prover))
                });
            });

        let proof = setup
            .secret
            .prove(setup.input, setup.output, b"ad", &prover);
        let verifier_key = setup.params.verifier_key(&setup.ring);
        let commitment = verifier_key.commitment();
        let verifier = setup.params.verifier(verifier_key.clone());

        c.benchmark_group(format!("{}/ring_verify", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    <ark_vrf::Public<S> as Verifier<S>>::verify(
                        setup.input,
                        setup.output,
                        b"ad",
                        black_box(&proof),
                        black_box(&verifier),
                    )
                    .unwrap()
                });
            });

        c.benchmark_group(format!("{}/ring_verifier_from_key", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.verifier(black_box(verifier_key.clone())));
            });

        c.benchmark_group(format!("{}/ring_vk_from_commitment", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    setup
                        .params
                        .verifier_key_from_commitment(black_box(commitment.clone()))
                });
            });

        c.benchmark_group(format!("{}/ring_vk_builder_create", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.verifier_key_builder());
            });

        let (mut builder, builder_pcs_params) = setup.params.verifier_key_builder();

        c.benchmark_group(format!("{}/ring_vk_builder_append", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    builder
                        .clone()
                        .append(black_box(&setup.ring), &builder_pcs_params)
                        .unwrap();
                });
            });

        builder.append(&setup.ring, &builder_pcs_params).unwrap();

        c.benchmark_group(format!("{}/ring_vk_builder_finalize", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| black_box(builder.clone()).finalize());
            });
    }
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

struct BatchItem<S: RingSuite> {
    input: Input<S>,
    output: Output<S>,
    ad: Vec<u8>,
    proof: ring::Proof<S>,
}

fn batch_benches<S: BenchInfo + RingSuite>(c: &mut Criterion) {
    let setup = make_ring_setup::<S>(1023);

    let prover_key = setup.params.prover_key(&setup.ring);
    let prover = setup.params.prover(prover_key, setup.prover_idx);

    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    println!("Preparing {max_batch_size} {} proofs...", S::SUITE_NAME);
    let completed = std::sync::atomic::AtomicUsize::new(0);
    let batch_items: Vec<BatchItem<S>> = (0..max_batch_size)
        .into_par_iter()
        .map_init(
            || rand_chacha::ChaCha20Rng::from_seed([0; 32]),
            |rng, i| {
                let input = Input::<S>::from_affine(AffinePoint::<S>::rand(rng));
                let output = setup.secret.output(input);
                let ad = format!("ad-{i}").into_bytes();
                let proof = setup.secret.prove(input, output, &ad, &prover);
                let prev = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let prev_pct = prev * 10 / max_batch_size;
                let curr_pct = (prev + 1) * 10 / max_batch_size;
                if curr_pct > prev_pct {
                    println!("  {}%", curr_pct * 10);
                }
                BatchItem {
                    input,
                    output,
                    ad,
                    proof,
                }
            },
        )
        .collect();

    let verifier_key = setup.params.verifier_key(&setup.ring);

    // batch_verifier_new: cost is independent of batch size, bench once.
    c.benchmark_group(format!("{}/batch_verifier_new", S::SUITE_NAME))
        .sample_size(10)
        .bench_function("batch_verifier_new", |b| {
            b.iter(|| {
                let vk = verifier_key.clone();
                let verifier = setup.params.verifier(vk);
                BatchVerifier::<S>::new(black_box(verifier))
            });
        });

    // A single BatchVerifier for prepare benchmarks (prepare takes &self).
    let vk = verifier_key.clone();
    let verifier = setup.params.verifier(vk);
    let batch_verifier = BatchVerifier::<S>::new(verifier);

    for &batch_size in BATCH_SIZES {
        let id = BenchmarkId::from_parameter(batch_size);

        // batch_push: sequential push of batch_size items.
        c.benchmark_group(format!("{}/batch_push", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter_batched(
                    || {
                        let vk = verifier_key.clone();
                        let verifier = setup.params.verifier(vk);
                        BatchVerifier::<S>::new(verifier)
                    },
                    |mut bv| {
                        for item in &batch_items[..batch_size] {
                            bv.push(item.input, item.output, &item.ad, &item.proof);
                        }
                    },
                    BatchSize::LargeInput,
                );
            });

        // batch_prepare_seq: sequential prepare of batch_size items.
        c.benchmark_group(format!("{}/batch_prepare_seq", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .iter()
                        .map(|item| {
                            batch_verifier.prepare(item.input, item.output, &item.ad, &item.proof)
                        })
                        .collect();
                });
            });

        // batch_prepare_par: parallel prepare of batch_size items.
        c.benchmark_group(format!("{}/batch_prepare_par", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .par_iter()
                        .map(|item| {
                            batch_verifier.prepare(item.input, item.output, &item.ad, &item.proof)
                        })
                        .collect();
                });
            });

        // batch_push_prepared: push_prepared of pre-prepared items.
        c.benchmark_group(format!("{}/batch_push_prepared", S::SUITE_NAME))
            .sample_size(10)
            .bench_function(id.clone(), |b| {
                b.iter_batched(
                    || {
                        let prepared = batch_items[..batch_size]
                            .iter()
                            .map(|item| {
                                batch_verifier.prepare(
                                    item.input,
                                    item.output,
                                    &item.ad,
                                    &item.proof,
                                )
                            })
                            .collect::<Vec<_>>();
                        let vk = verifier_key.clone();
                        let verifier = setup.params.verifier(vk);
                        let bv = BatchVerifier::<S>::new(verifier);
                        (bv, prepared)
                    },
                    |(mut bv, prepared)| {
                        for item in prepared {
                            bv.push_prepared(item);
                        }
                    },
                    BatchSize::LargeInput,
                );
            });

        // batch_verify: verify a fully-populated batch.
        {
            let vk = verifier_key.clone();
            let verifier = setup.params.verifier(vk);
            let mut bv = BatchVerifier::<S>::new(verifier);
            for item in &batch_items[..batch_size] {
                bv.push(item.input, item.output, &item.ad, &item.proof);
            }

            c.benchmark_group(format!("{}/batch_verify", S::SUITE_NAME))
                .sample_size(10)
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
                });
        }
    }
}

fn bench_ring_suite<S: BenchInfo + RingSuite>(c: &mut Criterion) {
    ring_benches::<S>(c);
    batch_benches::<S>(c);
}

fn bench_ring(c: &mut Criterion) {
    for_each_ring_suite!(c, bench_ring_suite);
}

criterion_group!(benches, bench_ring);

criterion_main!(benches);
