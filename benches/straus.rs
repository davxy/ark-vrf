#[macro_use]
mod bench_utils;

use ark_std::UniformRand;
use ark_vrf::utils::straus::short_msm;
use ark_vrf::{AffinePoint, ScalarField};
use bench_utils::BenchInfo;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

const POINT_COUNTS: &[usize] = &[2, 3, 4, 5];
const WINDOW_SIZES: &[usize] = &[1, 2, 3, 4];

fn bench_straus_suite<S: BenchInfo>(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();

    for &n in POINT_COUNTS {
        let points: Vec<AffinePoint<S>> = (0..n).map(|_| AffinePoint::<S>::rand(rng)).collect();
        let scalars: Vec<ScalarField<S>> = (0..n).map(|_| ScalarField::<S>::rand(rng)).collect();

        for &w in WINDOW_SIZES {
            c.benchmark_group(format!("{}/straus_msm/n={n}", S::SUITE_NAME))
                .bench_function(BenchmarkId::from_parameter(format!("w={w}")), |b| {
                    b.iter(|| short_msm(black_box(&points), black_box(&scalars), w));
                });
        }
    }
}

fn bench_straus(c: &mut Criterion) {
    for_each_suite!(c, bench_straus_suite);
}

criterion_group!(benches, bench_straus);

criterion_main!(benches);
