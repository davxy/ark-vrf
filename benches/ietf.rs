use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_vrf::suites::bandersnatch::*;

fn make_input() -> Input {
    Input::new(b"bench input data").unwrap()
}

fn make_secret() -> Secret {
    Secret::from_seed(b"bench secret seed")
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
                .verify(
                    black_box(input),
                    black_box(output),
                    b"ad",
                    black_box(&proof),
                )
                .unwrap()
        });
    });
}

criterion_group!(benches, bench_ietf_prove, bench_ietf_verify,);

criterion_main!(benches);
