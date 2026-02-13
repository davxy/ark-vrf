use ark_std::{rand::SeedableRng, UniformRand};
use ark_vrf::{
    ring::{Prover, Verifier},
    suites::bandersnatch::*,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

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
            .bench_with_input(id.clone(), &n, |b, &n| {
                b.iter(|| {
                    RingProofParams::from_pcs_params(black_box(n), setup.params.pcs.clone())
                        .unwrap()
                });
            });

        c.benchmark_group("bandersnatch/ring_prover_key")
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| setup.params.prover_key(black_box(&setup.ring)));
            });

        c.benchmark_group("bandersnatch/ring_verifier_key")
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| setup.params.verifier_key(black_box(&setup.ring)));
            });

        let prover_key = setup.params.prover_key(&setup.ring);
        let prover = setup.params.prover(prover_key, setup.prover_idx);

        c.benchmark_group("bandersnatch/ring_prove")
            .bench_with_input(id.clone(), &n, |b, _| {
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
            .bench_with_input(id.clone(), &n, |b, _| {
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
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| {
                    setup
                        .params
                        .verifier(black_box(setup.params.clone_verifier_key(&verifier_key)))
                });
            });

        c.benchmark_group("bandersnatch/ring_vk_from_commitment")
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| {
                    setup
                        .params
                        .verifier_key_from_commitment(black_box(commitment.clone()))
                });
            });

        c.benchmark_group("bandersnatch/ring_vk_builder_create")
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| setup.params.verifier_key_builder());
            });

        let (mut builder, builder_pcs_params) = setup.params.verifier_key_builder();

        c.benchmark_group("bandersnatch/ring_vk_builder_append")
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| {
                    builder
                        .clone()
                        .append(black_box(&setup.ring), &builder_pcs_params)
                        .unwrap();
                });
            });

        builder.append(&setup.ring, &builder_pcs_params).unwrap();

        c.benchmark_group("bandersnatch/ring_vk_builder_finalize")
            .bench_with_input(id.clone(), &n, |b, _| {
                b.iter(|| black_box(builder.clone()).finalize());
            });
    }
}

// Default sample_size is 100, which is too slow for ring operations that
// take seconds per iteration. Use 10 samples to keep total bench time reasonable.
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = ring_benches,
}

criterion_main!(benches);
