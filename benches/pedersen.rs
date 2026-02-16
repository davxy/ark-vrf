use ark_std::{UniformRand, rand::SeedableRng};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use ark_vrf::suites::bandersnatch::*;

fn make_input() -> Input {
    Input::new(b"bench input data").unwrap()
}

fn make_secret() -> Secret {
    Secret::from_seed(b"bench secret seed")
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
            Public::verify(
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

struct PedersenBatchItem {
    input: Input,
    output: Output,
    ad: Vec<u8>,
    proof: PedersenProof,
}

fn bench_pedersen_batch(c: &mut Criterion) {
    use ark_vrf::pedersen::{BatchVerifier, Prover};

    let secret = make_secret();
    let max_batch_size = BATCH_SIZES[BATCH_SIZES.len() - 1];

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let batch_items: Vec<PedersenBatchItem> = (0..max_batch_size)
        .map(|i| {
            let input = Input::from(AffinePoint::rand(&mut rng));
            let output = secret.output(input);
            let ad = format!("ad-{i}").into_bytes();
            let (proof, _) = secret.prove(input, output, &ad);
            PedersenBatchItem {
                input,
                output,
                ad,
                proof,
            }
        })
        .collect();

    for &batch_size in BATCH_SIZES {
        let id = BenchmarkId::from_parameter(batch_size);

        c.benchmark_group("bandersnatch/pedersen_batch_prepare")
            .bench_function(id.clone(), |b| {
                b.iter(|| {
                    let _: Vec<_> = batch_items[..batch_size]
                        .iter()
                        .map(|item| {
                            BatchVerifier::<BandersnatchSha512Ell2>::prepare(
                                item.input,
                                item.output,
                                &item.ad,
                                &item.proof,
                            )
                        })
                        .collect();
                });
            });

        {
            let mut bv = BatchVerifier::<BandersnatchSha512Ell2>::new();
            for item in &batch_items[..batch_size] {
                bv.push(item.input, item.output, &item.ad, &item.proof);
            }

            c.benchmark_group("bandersnatch/pedersen_batch_verify")
                .bench_function(id, |b| {
                    b.iter(|| bv.verify().unwrap());
                });
        }
    }
}

criterion_group!(benches, bench_pedersen_prove, bench_pedersen_verify,);

criterion_group! {
    name = pedersen_batch_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pedersen_batch,
}

criterion_main!(benches, pedersen_batch_benches);
