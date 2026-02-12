use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_vrf::suites::bandersnatch::*;

const RING_SIZE: usize = 1023;

struct RingSetup {
    secret: Secret,
    input: Input,
    output: Output,
    ring: Vec<AffinePoint>,
    prover_idx: usize,
    params: RingProofParams,
}

fn make_ring_setup() -> RingSetup {
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let secret = Secret::from_seed(b"bench secret seed");
    let public = secret.public();
    let input = Input::new(b"bench input data").unwrap();
    let output = secret.output(input);

    let prover_idx = 3;
    let mut ring: Vec<AffinePoint> = (0..RING_SIZE)
        .map(|_| AffinePoint::rand(&mut rng))
        .collect();
    ring[prover_idx] = public.0;

    let params = RingProofParams::from_rand(RING_SIZE, &mut rng);

    RingSetup {
        secret,
        input,
        output,
        ring,
        prover_idx,
        params,
    }
}

fn make_prover(setup: &RingSetup) -> ark_vrf::ring::RingProver<BandersnatchSha512Ell2> {
    let prover_key = setup.params.prover_key(&setup.ring);
    setup.params.prover(prover_key, setup.prover_idx)
}

fn make_verifier(setup: &RingSetup) -> ark_vrf::ring::RingVerifier<BandersnatchSha512Ell2> {
    let verifier_key = setup.params.verifier_key(&setup.ring);
    setup.params.verifier(verifier_key)
}

fn bench_ring_params_setup(c: &mut Criterion) {
    use ark_std::rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([99; 32]);
    let params = RingProofParams::from_rand(RING_SIZE, &mut rng);

    c.bench_function(
        &format!("bandersnatch/ring_params_setup (n={RING_SIZE})"),
        |b| {
            b.iter(|| {
                RingProofParams::from_pcs_params(black_box(RING_SIZE), params.pcs.clone()).unwrap()
            });
        },
    );
}

fn bench_ring_prover_key(c: &mut Criterion) {
    let setup = make_ring_setup();

    c.bench_function(
        &format!("bandersnatch/ring_prover_key (n={RING_SIZE})"),
        |b| {
            b.iter(|| setup.params.prover_key(black_box(&setup.ring)));
        },
    );
}

fn bench_ring_verifier_key(c: &mut Criterion) {
    let setup = make_ring_setup();

    c.bench_function(
        &format!("bandersnatch/ring_verifier_key (n={RING_SIZE})"),
        |b| {
            b.iter(|| setup.params.verifier_key(black_box(&setup.ring)));
        },
    );
}

fn bench_ring_prove(c: &mut Criterion) {
    use ark_vrf::ring::Prover;
    let setup = make_ring_setup();
    let prover = make_prover(&setup);

    c.bench_function(&format!("bandersnatch/ring_prove (n={RING_SIZE})"), |b| {
        b.iter(|| {
            setup
                .secret
                .prove(setup.input, setup.output, b"ad", black_box(&prover))
        });
    });
}

fn bench_ring_verify(c: &mut Criterion) {
    use ark_vrf::ring::{Prover, Verifier};
    let setup = make_ring_setup();
    let prover = make_prover(&setup);
    let proof = setup
        .secret
        .prove(setup.input, setup.output, b"ad", &prover);
    let verifier = make_verifier(&setup);

    c.bench_function(&format!("bandersnatch/ring_verify (n={RING_SIZE})"), |b| {
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
}

fn bench_ring_verifier_from_key(c: &mut Criterion) {
    let setup = make_ring_setup();
    let verifier_key = setup.params.verifier_key(&setup.ring);

    c.bench_function(
        &format!("bandersnatch/ring_verifier_from_key (n={RING_SIZE})"),
        |b| {
            b.iter(|| setup.params.verifier(black_box(verifier_key.clone())));
        },
    );
}

fn bench_ring_verifier_key_from_commitment(c: &mut Criterion) {
    let setup = make_ring_setup();
    let verifier_key = setup.params.verifier_key(&setup.ring);
    let commitment = verifier_key.commitment();

    c.bench_function(
        &format!("bandersnatch/ring_vk_from_commitment (n={RING_SIZE})"),
        |b| {
            b.iter(|| {
                setup
                    .params
                    .verifier_key_from_commitment(black_box(commitment.clone()))
            });
        },
    );
}

fn bench_ring_verifier_key_builder(c: &mut Criterion) {
    let setup = make_ring_setup();
    let (_, builder_pcs_params) = setup.params.verifier_key_builder();

    c.bench_function(
        &format!("bandersnatch/ring_vk_builder (n={RING_SIZE})"),
        |b| {
            b.iter(|| {
                let (mut builder, _) = setup.params.verifier_key_builder();
                builder
                    .append(black_box(&setup.ring), &builder_pcs_params)
                    .unwrap();
                builder.finalize()
            });
        },
    );
}

// Default sample_size is 100, which is too slow for ring operations that
// take seconds per iteration. Use 10 samples to keep total bench time reasonable.
criterion_group! {
    name = ring_benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_ring_params_setup,
        bench_ring_prover_key,
        bench_ring_verifier_key,
        bench_ring_prove,
        bench_ring_verify,
        bench_ring_verifier_from_key,
        bench_ring_verifier_key_from_commitment,
        bench_ring_verifier_key_builder,
}

criterion_main!(ring_benches);
