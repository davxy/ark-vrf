use ark_std::{rand::SeedableRng, UniformRand};
use ark_vrf::{
    ring::{BatchVerifier, Prover, Verifier},
    suites::bandersnatch::*,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rayon::prelude::*;

const RING_SIZES: [usize; 3] = [255, 1023, 2047];

struct RingSetup {
    secret: Secret,
    input: Input,
    output: Output,
    ring: Vec<AffinePoint>,
    prover_idx: usize,
    params: RingProofParams,
}

fn make_ring_setup(ring_size: usize) -> RingSetup {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let secret = Secret::from_seed(b"bench secret seed");
    let public = secret.public();
    let input = Input::new(b"bench input data").unwrap();
    let output = secret.output(input);

    let prover_idx = 3;
    let mut ring: Vec<AffinePoint> = (0..ring_size)
        .map(|_| AffinePoint::rand(&mut rng))
        .collect();
    ring[prover_idx] = public.0;

    let params = RingProofParams::from_rand(ring_size, &mut rng);

    RingSetup {
        secret,
        input,
        output,
        ring,
        prover_idx,
        params,
    }
}

fn ring_benches(c: &mut Criterion) {
    for &n in &RING_SIZES {
        let setup = make_ring_setup(n);
        let id = BenchmarkId::from_parameter(n);

        c.benchmark_group("bandersnatch/ring_params_setup")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    RingProofParams::from_pcs_params(black_box(n), setup.params.pcs.clone())
                        .unwrap()
                });
            });

        c.benchmark_group("bandersnatch/ring_prover_key")
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.prover_key(black_box(&setup.ring)));
            });

        c.benchmark_group("bandersnatch/ring_verifier_key")
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.verifier_key(black_box(&setup.ring)));
            });

        let prover_key = setup.params.prover_key(&setup.ring);
        let prover = setup.params.prover(prover_key, setup.prover_idx);

        c.benchmark_group("bandersnatch/ring_prove")
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
        let verifier = setup
            .params
            .verifier(setup.params.clone_verifier_key(&verifier_key));

        c.benchmark_group("bandersnatch/ring_verify")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    Public::verify(
                        setup.input,
                        setup.output,
                        b"ad",
                        black_box(&proof),
                        black_box(&verifier),
                    )
                    .unwrap()
                });
            });

        c.benchmark_group("bandersnatch/ring_verifier_from_key")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    setup
                        .params
                        .verifier(black_box(setup.params.clone_verifier_key(&verifier_key)))
                });
            });

        c.benchmark_group("bandersnatch/ring_vk_from_commitment")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    setup
                        .params
                        .verifier_key_from_commitment(black_box(commitment.clone()))
                });
            });

        c.benchmark_group("bandersnatch/ring_vk_builder_create")
            .bench_function(id.clone(), |b| {
                b.iter(|| setup.params.verifier_key_builder());
            });

        let (mut builder, builder_pcs_params) = setup.params.verifier_key_builder();

        c.benchmark_group("bandersnatch/ring_vk_builder_append")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    builder
                        .clone()
                        .append(black_box(&setup.ring), &builder_pcs_params)
                        .unwrap();
                });
            });

        builder.append(&setup.ring, &builder_pcs_params).unwrap();

        c.benchmark_group("bandersnatch/ring_vk_builder_finalize")
            .bench_function(id.clone(), |b| {
                b.iter(|| black_box(builder.clone()).finalize());
            });
    }
}

struct BatchItem {
    input: Input,
    output: Output,
    ad: Vec<u8>,
    proof: RingProof,
}

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

fn batch_benches(c: &mut Criterion) {
    let setup = make_ring_setup(1023);

    let prover_key = setup.params.prover_key(&setup.ring);
    let prover = setup.params.prover(prover_key, setup.prover_idx);

    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    println!("Preparing {max_batch_size} proofs...");
    let completed = std::sync::atomic::AtomicUsize::new(0);
    let batch_items: Vec<BatchItem> = (0..max_batch_size)
        .into_par_iter()
        .map_init(
            || rand_chacha::ChaCha20Rng::from_seed([0; 32]),
            |rng, i| {
                let input = Input::from(AffinePoint::rand(rng));
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
    c.benchmark_group("bandersnatch/batch_verifier_new")
        .bench_function("batch_verifier_new", |b| {
            b.iter(|| {
                let vk = setup.params.clone_verifier_key(&verifier_key);
                let verifier = setup.params.verifier(vk);
                BatchVerifier::<BandersnatchSha512Ell2>::new(black_box(verifier))
            });
        });

    // A single BatchVerifier for prepare benchmarks (prepare takes &self).
    let vk = setup.params.clone_verifier_key(&verifier_key);
    let verifier = setup.params.verifier(vk);
    let batch_verifier = BatchVerifier::new(verifier);

    for &batch_size in BATCH_SIZES {
        let id = BenchmarkId::from_parameter(batch_size);

        // batch_push: sequential push of batch_size items.
        c.benchmark_group("bandersnatch/batch_push")
            .bench_function(id.clone(), |b| {
                b.iter_batched(
                    || {
                        let vk = setup.params.clone_verifier_key(&verifier_key);
                        let verifier = setup.params.verifier(vk);
                        BatchVerifier::new(verifier)
                    },
                    |mut bv| {
                        for item in &batch_items[..batch_size] {
                            bv.push(item.input, item.output, &item.ad, &item.proof)
                                .unwrap();
                        }
                    },
                    BatchSize::LargeInput,
                );
            });

        // batch_prepare_seq: sequential prepare of batch_size items.
        c.benchmark_group("bandersnatch/batch_prepare_seq")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .iter()
                        .map(|item| {
                            batch_verifier
                                .prepare(item.input, item.output, &item.ad, &item.proof)
                                .unwrap()
                        })
                        .collect();
                });
            });

        // batch_prepare_par: parallel prepare of batch_size items.
        c.benchmark_group("bandersnatch/batch_prepare_par")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .par_iter()
                        .map(|item| {
                            batch_verifier
                                .prepare(item.input, item.output, &item.ad, &item.proof)
                                .unwrap()
                        })
                        .collect();
                });
            });

        // batch_push_prepared: push_prepared of pre-prepared items.
        c.benchmark_group("bandersnatch/batch_push_prepared")
            .bench_function(id.clone(), |b| {
                b.iter_batched(
                    || {
                        let prepared = batch_items[..batch_size]
                            .iter()
                            .map(|item| {
                                batch_verifier
                                    .prepare(item.input, item.output, &item.ad, &item.proof)
                                    .unwrap()
                            })
                            .collect::<Vec<_>>();
                        let vk = setup.params.clone_verifier_key(&verifier_key);
                        let verifier = setup.params.verifier(vk);
                        let bv = BatchVerifier::<BandersnatchSha512Ell2>::new(verifier);
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
            let vk = setup.params.clone_verifier_key(&verifier_key);
            let verifier = setup.params.verifier(vk);
            let mut bv = BatchVerifier::new(verifier);
            for item in &batch_items[..batch_size] {
                bv.push(item.input, item.output, &item.ad, &item.proof)
                    .unwrap();
            }

            c.benchmark_group("bandersnatch/batch_verify")
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
                });
        }
    }
}

// Default sample_size is 100, which is too slow for ring operations that
// take seconds per iteration. Use 10 samples to keep total bench time reasonable.
criterion_group! {
    name = ring_benches_group;
    config = Criterion::default().sample_size(10);
    targets = ring_benches,
}

criterion_group! {
    name = batch_benches_group;
    config = Criterion::default().sample_size(10);
    targets = batch_benches,
}

criterion_main!(batch_benches_group, ring_benches_group);
