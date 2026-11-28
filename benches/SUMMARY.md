# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-11-28, at `3d248e6`
Features: `full`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.11 (crates.io)
Criterion: 0.5.1, `--quick` mode. Each value is the median of five runs.

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 7.3.5
- Rust: 1.98.1 (48a229cea 2026-09-01)

## Common Operations (`common.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| vrf_output             | 78.86 us |
| data_to_point_tai      | 20.60 us |
| data_to_point_ell2     | 67.26 us |
| point_to_hash          | 642.6 ns |
| challenge              | 1.127 us |
| nonce                  | 2.132 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 136.7 us |
| tiny_verify            | 122.9 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 382.1 us |
| pedersen_verify        | 213.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.218 us | 2.430 us | 4.856 us | 9.692 us | 19.23 us | 38.84 us | 76.73 us | 155.2 us | 310.5 us |
| batch_verify         | 513.1 us | 601.2 us | 774.3 us | 1.756 ms | 2.134 ms | 3.592 ms | 6.226 ms | 8.613 ms | 15.52 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 133.3 us |
| thin_verify            | 127.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.901 us | 3.783 us | 7.507 us | 15.02 us | 30.05 us | 61.62 us | 121.4 us | 249.9 us | 485.2 us |
| batch_verify         | 478.5 us | 552.0 us | 705.2 us | 1.636 ms | 2.026 ms | 3.408 ms | 5.865 ms | 7.725 ms | 13.96 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  843.7 us |  3.845 ms |  8.021 ms |
| ring_context_setup       |  836.0 us |  3.829 ms |  8.167 ms |
| ring_prover_key          |  38.11 ms |  117.3 ms |  215.3 ms |
| ring_verifier_key        |  37.97 ms |  117.5 ms |  215.7 ms |
| ring_keys                |  37.98 ms |  117.2 ms |  214.8 ms |
| ring_prove               |  129.2 ms |  409.0 ms |  727.8 ms |
| ring_verify              |  3.071 ms |  3.253 ms |  3.102 ms |
| ring_verifier_from_key   |  246.0 us |  273.9 us |  303.7 us |
| ring_vk_from_commitment  |  48.49 ns |  49.28 ns |  48.27 ns |
| ring_vk_builder_create   |  292.1 ms |   1.392 s |   3.035 s |
| ring_vk_builder_append   |  13.82 ms |  41.16 ms |  72.38 ms |
| ring_vk_builder_finalize |  79.59 ns |  79.73 ns |  81.22 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.968 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 46.11 us | 92.83 us | 186.9 us | 402.1 us | 847.2 us | 1.717 ms | 3.525 ms | 6.737 ms | 13.80 ms |
| batch_prepare_seq  | 43.94 us | 90.61 us | 187.8 us | 392.5 us | 826.9 us | 1.694 ms | 3.334 ms | 6.663 ms | 13.61 ms |
| batch_prepare_par  | 45.04 us | 84.87 us | 119.9 us | 181.1 us | 235.6 us | 269.7 us | 400.3 us | 719.3 us | 1.108 ms |
| batch_push_prepared| 692.8 ns | 1.169 us | 2.450 us | 5.170 us | 10.23 us | 20.72 us | 41.57 us | 80.03 us | 152.2 us |
| batch_verify       | 3.304 ms | 3.919 ms | 5.284 ms | 7.840 ms | 10.98 ms | 17.74 ms | 28.00 ms | 46.47 ms | 83.72 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  118.1 us |  90.45 us |  98.88 us |  160.4 us |
|   3 |  121.0 us |  108.8 us |  268.4 us |  1.622 ms |
|   4 |  124.7 us |  180.7 us |  1.637 ms |  25.01 ms |
|   5 |  132.4 us |  480.2 us |  12.56 ms |  424.6 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.1 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 129 ms at n=255, 409 ms at n=1023,
  728 ms at n=2047.
- `ring_keys` costs one indexing pass, the same as either single-key method,
  so a party that needs both keys pays about half of the two calls.
- `ring_vk_builder_create` is the most expensive operation (up to 3.04 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.84 ms at n=255,
  ~3.8 ms at n=1023, ~8.1 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (274 us) + n * `ring_verify` (3.25 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~53 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.0 ms base + ~0.30 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.055 ms/proof, leaving ~0.25 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.053 ms (prepare) + ~0.303 ms (verify) = ~0.356 ms,
or ~9.1x cheaper than simple verification (3.25 ms). With parallel prepare, the
per-proof prepare cost drops to ~4.3 us at n=256, giving ~0.31 ms marginal, or ~10.6x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.53 ms  |    3.35 ms  |    3.35 ms  |         1.05x |         1.05x |
|   2 |    6.78 ms  |    4.01 ms  |    4.00 ms  |         1.69x |         1.69x |
|   4 |   13.29 ms  |    5.47 ms  |    5.40 ms  |         2.43x |         2.46x |
|   8 |   26.30 ms  |    8.23 ms  |    8.02 ms  |         3.19x |         3.28x |
|  16 |   52.32 ms  |   11.80 ms  |   11.21 ms  |         4.43x |         4.67x |
|  32 |  104.37 ms  |   19.43 ms  |   18.01 ms  |         5.37x |         5.80x |
|  64 |  208.47 ms  |   31.33 ms  |   28.40 ms  |         6.65x |         7.34x |
| 128 |  416.67 ms  |   53.13 ms  |   47.19 ms  |         7.84x |         8.83x |
| 256 |  833.07 ms  |   97.33 ms  |   84.83 ms  |         8.56x |         9.82x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.30 ms |  3.30 ms  |
|   2 |    3.92 ms |  1.96 ms  |
|   4 |    5.28 ms |  1.32 ms  |
|   8 |    7.84 ms |  0.98 ms  |
|  16 |   10.98 ms |  0.69 ms  |
|  32 |   17.74 ms |  0.55 ms  |
|  64 |   28.00 ms |  0.44 ms  |
| 128 |   46.47 ms |  0.36 ms  |
| 256 |   83.72 ms |  0.33 ms  |

Amortized cost per proof drops from 3.30 ms (n=1) to 0.33 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.8 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).

## Comparison with 0.6.2

The `v0.6.2` tag ran on the same machine and day as the tables above, with
the same lock file, so all dependencies have the same versions. The two
versions alternated for each bench binary, five times. The values are the
medians of the five runs.

| Benchmark                     |    0.6.2 |     HEAD | Change |
|:------------------------------|---------:|---------:|-------:|
| vrf_output                    | 79.61 us | 78.86 us |  -0.9% |
| data_to_point_tai             | 20.93 us | 20.60 us |  -1.5% |
| data_to_point_ell2            | 66.75 us | 67.26 us |  +0.8% |
| point_to_hash                 | 645.1 ns | 642.6 ns |  -0.4% |
| challenge                     | 1.145 us | 1.127 us |  -1.6% |
| nonce                         | 2.132 us | 2.132 us |  -0.0% |
| tiny_prove                    | 130.0 us | 136.7 us |  +5.1% |
| tiny_verify                   | 124.8 us | 122.9 us |  -1.5% |
| thin_prove                    | 133.7 us | 133.3 us |  -0.4% |
| thin_verify                   | 124.3 us | 127.5 us |  +2.6% |
| thin batch_verify n=256       | 14.19 ms | 13.96 ms |  -1.6% |
| pedersen_prove                | 378.7 us | 382.1 us |  +0.9% |
| pedersen_verify               | 207.8 us | 213.5 us |  +2.7% |
| pedersen batch_verify n=256   | 15.31 ms | 15.52 ms |  +1.3% |
| ring_prover_key n=1023        | 113.2 ms | 117.3 ms |  +3.6% |
| ring_verifier_key n=1023      | 112.7 ms | 117.5 ms |  +4.3% |
| ring_prove n=1023             | 395.9 ms | 409.0 ms |  +3.3% |
| ring_verify n=1023            | 3.061 ms | 3.253 ms |  +6.3% |
| ring_vk_builder_create n=1023 |  1.365 s |  1.392 s |  +2.0% |
| ring batch_verify n=256       | 82.14 ms | 83.72 ms |  +1.9% |

- Since 0.6.2 the Thin and Pedersen batch weights absorb all the values of the
  batch equation. A direct measurement gives about 0.5 us per proof, which is
  about 1% of `batch_verify` at n=256. The `batch_verify` rows of Thin, Pedersen
  and Ring moved by -5.9% to +1.9%, which is less than the noise.
- `pedersen_verify` moved by +2.7%, and the ranges of the five runs overlap.
  Since 0.6.2 it rejects a result with Z = 0, which an off-curve key commitment
  or output from the unchecked path can give. The check reads Z and has no
  measurable cost.
- The Straus rows, whose code did not change, moved by -3.1% to +9.1%:
  this is the noise of the method. All other rows are within 11% of 0.6.2.
  The largest change is `batch_push_prepared` (ring) at n=256 (-10.8%). Its
  code did not change, and the ranges of the five runs overlap.
- The ranges of the five runs of the two versions do not overlap in 7 rows,
  also in 2 Straus rows. Thus a gap between the ranges is also in the noise.
