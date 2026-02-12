use criterion::{Criterion, black_box, criterion_group, criterion_main};

use ark_vrf::suites::bandersnatch::*;

fn make_input() -> Input {
    Input::new(b"bench input data").unwrap()
}

fn make_secret() -> Secret {
    Secret::from_seed(b"bench secret seed")
}

fn bench_hash_to_curve(c: &mut Criterion) {
    c.bench_function("bandersnatch/hash_to_curve", |b| {
        b.iter(|| Input::new(black_box(b"bench input data")).unwrap());
    });
}

fn bench_vrf_output(c: &mut Criterion) {
    let secret = make_secret();
    let input = make_input();
    c.bench_function("bandersnatch/vrf_output", |b| {
        b.iter(|| secret.output(black_box(input)));
    });
}

fn bench_output_hash(c: &mut Criterion) {
    let secret = make_secret();
    let input = make_input();
    let output = secret.output(input);
    c.bench_function("bandersnatch/output_hash", |b| {
        b.iter(|| black_box(&output).hash());
    });
}

fn bench_ietf_prove(c: &mut Criterion) {
    use ark_vrf::ietf::Prover;

    let secret = make_secret();
    let input = make_input();
    let output = secret.output(input);

    c.bench_function("bandersnatch/ietf_prove", |b| {
        b.iter(|| secret.prove(black_box(input), black_box(output), b"ad"));
    });
}

fn bench_ietf_verify(c: &mut Criterion) {
    use ark_vrf::ietf::{Prover, Verifier};

    let secret = make_secret();
    let public = secret.public();
    let input = make_input();
    let output = secret.output(input);
    let proof = secret.prove(input, output, b"ad");

    c.bench_function("bandersnatch/ietf_verify", |b| {
        b.iter(|| {
            public
                .verify(black_box(input), black_box(output), b"ad", black_box(&proof))
                .unwrap()
        });
    });
}

fn bench_pedersen_prove(c: &mut Criterion) {
    use ark_vrf::pedersen::Prover;

    let secret = make_secret();
    let input = make_input();
    let output = secret.output(input);

    c.bench_function("bandersnatch/pedersen_prove", |b| {
        b.iter(|| secret.prove(black_box(input), black_box(output), b"ad"));
    });
}

fn bench_pedersen_verify(c: &mut Criterion) {
    use ark_vrf::pedersen::{Prover, Verifier};

    let secret = make_secret();
    let input = make_input();
    let output = secret.output(input);
    let (proof, _blinding) = secret.prove(input, output, b"ad");

    c.bench_function("bandersnatch/pedersen_verify", |b| {
        b.iter(|| {
            Public::verify(black_box(input), black_box(output), b"ad", black_box(&proof)).unwrap()
        });
    });
}

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("bandersnatch/key_from_seed", |b| {
        b.iter(|| Secret::from_seed(black_box(b"bench secret seed")));
    });
}

fn bench_nonce_generation(c: &mut Criterion) {
    use ark_vrf::Suite;

    let secret = make_secret();
    let input = make_input();

    c.bench_function("bandersnatch/nonce_generation", |b| {
        b.iter(|| {
            BandersnatchSha512Ell2::nonce(black_box(&secret.scalar), black_box(input))
        });
    });
}

fn bench_challenge_generation(c: &mut Criterion) {
    use ark_vrf::Suite;

    let secret = make_secret();
    let input = make_input();
    let output = secret.output(input);
    let generator = BandersnatchSha512Ell2::generator();

    c.bench_function("bandersnatch/challenge_generation", |b| {
        b.iter(|| {
            BandersnatchSha512Ell2::challenge(
                black_box(&[&secret.public().0, &input.0, &output.0, &generator, &generator]),
                b"ad",
            )
        });
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_hash_to_curve,
    bench_vrf_output,
    bench_output_hash,
    bench_nonce_generation,
    bench_challenge_generation,
    bench_ietf_prove,
    bench_ietf_verify,
    bench_pedersen_prove,
    bench_pedersen_verify,
);

criterion_main!(benches);
