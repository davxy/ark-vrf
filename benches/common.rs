use ark_std::{UniformRand, rand::SeedableRng};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use ark_vrf::suites::bandersnatch::*;
use ark_vrf::{Suite, utils};

fn make_input() -> Input {
    Input::new(b"bench input data").unwrap()
}

fn make_secret() -> Secret {
    Secret::from_seed(b"bench secret seed")
}

fn bench_key_from_seed(c: &mut Criterion) {
    c.bench_function("bandersnatch/key_from_seed", |b| {
        b.iter(|| Secret::from_seed(black_box(b"bench secret seed")));
    });
}

fn bench_key_from_scalar(c: &mut Criterion) {
    let secret = make_secret();
    c.bench_function("bandersnatch/key_from_scalar", |b| {
        b.iter(|| Secret::from_scalar(black_box(secret.scalar)));
    });
}

fn bench_vrf_output(c: &mut Criterion) {
    let secret = make_secret();
    let input = make_input();
    c.bench_function("bandersnatch/vrf_output", |b| {
        b.iter(|| secret.output(black_box(input)));
    });
}

// --- utils::common ---

fn bench_hash_sha512(c: &mut Criterion) {
    c.bench_function("bandersnatch/hash_sha512", |b| {
        b.iter(|| {
            utils::hash::<sha2::Sha512>(black_box(b"bench input data"));
        });
    });
}

fn bench_hash_to_curve_ell2_rfc_9380(c: &mut Criterion) {
    c.bench_function("bandersnatch/hash_to_curve_ell2_rfc_9380", |b| {
        b.iter(|| {
            utils::hash_to_curve_ell2_rfc_9380::<BandersnatchSha512Ell2>(
                black_box(b"bench input data"),
                b"Bandersnatch_XMD:SHA-512_ELL2_RO_",
            )
            .unwrap()
        });
    });
}

fn bench_hash_to_curve_tai_rfc_9381(c: &mut Criterion) {
    c.bench_function("bandersnatch/hash_to_curve_tai_rfc_9381", |b| {
        b.iter(|| {
            utils::hash_to_curve_tai_rfc_9381::<BandersnatchSha512Ell2>(black_box(
                b"bench input data",
            ))
            .unwrap()
        });
    });
}

fn bench_challenge_rfc_9381(c: &mut Criterion) {
    let secret = make_secret();
    let input = make_input();
    let output = secret.output(input);
    let generator = BandersnatchSha512Ell2::generator();

    c.bench_function("bandersnatch/challenge_rfc_9381", |b| {
        b.iter(|| {
            utils::challenge_rfc_9381::<BandersnatchSha512Ell2>(
                black_box(&[
                    &secret.public().0,
                    &input.0,
                    &output.0,
                    &generator,
                    &generator,
                ]),
                b"ad",
            )
        });
    });
}

fn bench_point_to_hash_rfc_9381(c: &mut Criterion) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let point = AffinePoint::rand(&mut rng);

    c.bench_function("bandersnatch/point_to_hash_rfc_9381", |b| {
        b.iter(|| {
            utils::point_to_hash_rfc_9381::<BandersnatchSha512Ell2>(black_box(&point), false)
        });
    });
}

fn bench_nonce_rfc_8032(c: &mut Criterion) {
    let secret = make_secret();
    let input = make_input();

    c.bench_function("bandersnatch/nonce_rfc_8032", |b| {
        b.iter(|| {
            utils::nonce_rfc_8032::<BandersnatchSha512Ell2>(
                black_box(&secret.scalar),
                black_box(&input.0),
            )
        });
    });
}

fn bench_nonce_rfc_6979(c: &mut Criterion) {
    let secret = make_secret();
    let input = make_input();

    c.bench_function("bandersnatch/nonce_rfc_6979", |b| {
        b.iter(|| {
            utils::nonce_rfc_6979::<BandersnatchSha512Ell2>(
                black_box(&secret.scalar),
                black_box(&input.0),
            )
        });
    });
}

// --- codec ---

fn bench_point_encode(c: &mut Criterion) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let point = AffinePoint::rand(&mut rng);

    c.bench_function("bandersnatch/point_encode", |b| {
        b.iter(|| ark_vrf::codec::point_encode::<BandersnatchSha512Ell2>(black_box(&point)));
    });
}

fn bench_point_decode(c: &mut Criterion) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let point = AffinePoint::rand(&mut rng);
    let encoded = ark_vrf::codec::point_encode::<BandersnatchSha512Ell2>(&point);

    c.bench_function("bandersnatch/point_decode", |b| {
        b.iter(|| {
            ark_vrf::codec::point_decode::<BandersnatchSha512Ell2>(black_box(&encoded)).unwrap()
        });
    });
}

fn bench_scalar_encode(c: &mut Criterion) {
    let secret = make_secret();

    c.bench_function("bandersnatch/scalar_encode", |b| {
        b.iter(|| {
            ark_vrf::codec::scalar_encode::<BandersnatchSha512Ell2>(black_box(&secret.scalar))
        });
    });
}

fn bench_scalar_decode(c: &mut Criterion) {
    let secret = make_secret();
    let encoded = ark_vrf::codec::scalar_encode::<BandersnatchSha512Ell2>(&secret.scalar);

    c.bench_function("bandersnatch/scalar_decode", |b| {
        b.iter(|| ark_vrf::codec::scalar_decode::<BandersnatchSha512Ell2>(black_box(&encoded)));
    });
}

criterion_group!(
    benches,
    bench_key_from_seed,
    bench_key_from_scalar,
    bench_vrf_output,
    bench_hash_sha512,
    bench_hash_to_curve_ell2_rfc_9380,
    bench_hash_to_curve_tai_rfc_9381,
    bench_challenge_rfc_9381,
    bench_point_to_hash_rfc_9381,
    bench_nonce_rfc_8032,
    bench_nonce_rfc_6979,
    bench_point_encode,
    bench_point_decode,
    bench_scalar_encode,
    bench_scalar_decode,
);

criterion_main!(benches);
