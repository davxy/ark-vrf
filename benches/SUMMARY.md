# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-11-05, at `1de1869`
Features: `full`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.11 (crates.io)
Criterion: 0.5.1, `--quick` mode. Each value is the median of five runs.

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 7.2.14
- Rust: 1.98.1 (48a229cea 2026-09-01)

## Common Operations (`common.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| vrf_output             | 81.38 us |
| data_to_point_tai      | 20.72 us |
| data_to_point_ell2     | 65.25 us |
| point_to_hash          | 645.7 ns |
| challenge              | 1.091 us |
| nonce                  | 2.050 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 134.0 us |
| tiny_verify            | 130.8 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 376.1 us |
| pedersen_verify        | 213.4 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.239 us | 2.467 us | 4.956 us | 9.922 us | 19.83 us | 39.59 us | 79.53 us | 158.0 us | 316.3 us |
| batch_verify         | 524.3 us | 610.5 us | 781.2 us | 1.809 ms | 2.161 ms | 3.559 ms | 6.155 ms | 8.567 ms | 15.41 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 135.0 us |
| thin_verify            | 124.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.891 us | 3.761 us | 7.529 us | 15.09 us | 30.23 us | 61.95 us | 123.9 us | 247.4 us | 493.8 us |
| batch_verify         | 479.3 us | 556.9 us | 709.3 us | 1.704 ms | 2.032 ms | 3.431 ms | 5.881 ms | 7.882 ms | 13.82 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  840.1 us |  3.851 ms |  8.316 ms |
| ring_context_setup       |  834.9 us |  3.825 ms |  8.243 ms |
| ring_prover_key          |  37.71 ms |  117.6 ms |  215.4 ms |
| ring_verifier_key        |  37.87 ms |  117.8 ms |  209.8 ms |
| ring_keys                |  37.80 ms |  118.4 ms |  210.4 ms |
| ring_prove               |  128.4 ms |  403.1 ms |  731.4 ms |
| ring_verify              |  3.199 ms |  3.183 ms |  3.203 ms |
| ring_verifier_from_key   |  253.2 us |  275.5 us |  302.7 us |
| ring_vk_from_commitment  |  47.42 ns |  47.70 ns |  48.82 ns |
| ring_vk_builder_create   |  301.0 ms |   1.380 s |   2.993 s |
| ring_vk_builder_append   |  13.10 ms |  38.73 ms |  68.93 ms |
| ring_vk_builder_finalize |  79.81 ns |  80.42 ns |  74.62 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 2.078 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 44.11 us | 88.16 us | 182.1 us | 388.9 us | 832.5 us | 1.625 ms | 3.257 ms | 6.502 ms | 13.20 ms |
| batch_prepare_seq  | 43.23 us | 91.83 us | 177.5 us | 382.6 us | 790.3 us | 1.623 ms | 3.202 ms | 6.780 ms | 12.84 ms |
| batch_prepare_par  | 43.33 us | 82.34 us | 125.7 us | 184.1 us | 264.1 us | 273.5 us | 378.1 us | 714.5 us | 1.080 ms |
| batch_push_prepared| 661.5 ns | 1.179 us | 2.369 us | 4.744 us | 9.645 us | 19.42 us | 37.72 us | 73.74 us | 146.6 us |
| batch_verify       | 3.252 ms | 3.912 ms | 5.224 ms | 7.671 ms | 10.76 ms | 17.42 ms | 27.63 ms | 45.67 ms | 81.07 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  111.9 us |  86.36 us |  94.40 us |  164.4 us |
|   3 |  114.7 us |  105.0 us |  272.9 us |  1.688 ms |
|   4 |  118.8 us |  181.1 us |  1.689 ms |  25.69 ms |
|   5 |  121.0 us |  492.5 us |  12.89 ms |  432.4 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 128 ms at n=255, 403 ms at n=1023,
  731 ms at n=2047.
- `ring_keys` costs one indexing pass, the same as either single-key method,
  so a party that needs both keys pays about half of the two calls.
- `ring_vk_builder_create` is the most expensive operation (up to 2.99 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.84 ms at n=255,
  ~3.8 ms at n=1023, ~8.3 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (276 us) + n * `ring_verify` (3.18 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~50 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.1 ms base + ~0.29 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.054 ms/proof, leaving ~0.24 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.050 ms (prepare) + ~0.293 ms (verify) = ~0.343 ms,
or ~9.3x cheaper than simple verification (3.18 ms). With parallel prepare, the
per-proof prepare cost drops to ~4.2 us at n=256, giving ~0.30 ms marginal, or ~10.7x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.46 ms  |    3.30 ms  |    3.30 ms  |         1.05x |         1.05x |
|   2 |    6.64 ms  |    4.00 ms  |    3.99 ms  |         1.66x |         1.66x |
|   4 |   13.01 ms  |    5.40 ms  |    5.35 ms  |         2.41x |         2.43x |
|   8 |   25.74 ms  |    8.05 ms  |    7.86 ms  |         3.20x |         3.28x |
|  16 |   51.20 ms  |   11.55 ms  |   11.02 ms  |         4.43x |         4.64x |
|  32 |  102.13 ms  |   19.04 ms  |   17.69 ms  |         5.36x |         5.77x |
|  64 |  203.97 ms  |   30.83 ms  |   28.01 ms  |         6.62x |         7.28x |
| 128 |  407.67 ms  |   52.45 ms  |   46.39 ms  |         7.77x |         8.79x |
| 256 |  815.07 ms  |   93.91 ms  |   82.15 ms  |         8.68x |         9.92x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.25 ms |  3.25 ms  |
|   2 |    3.91 ms |  1.96 ms  |
|   4 |    5.22 ms |  1.31 ms  |
|   8 |    7.67 ms |  0.96 ms  |
|  16 |   10.76 ms |  0.67 ms  |
|  32 |   17.42 ms |  0.54 ms  |
|  64 |   27.63 ms |  0.43 ms  |
| 128 |   45.67 ms |  0.36 ms  |
| 256 |   81.07 ms |  0.32 ms  |

Amortized cost per proof drops from 3.25 ms (n=1) to 0.32 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.7 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).

## Comparison with 0.6.1

The `v0.6.1` tag ran on the same machine and day as the tables above, with
the same lock file, so all dependencies have the same versions. The two
versions alternated for each bench binary, five times. The values are the
medians of the five runs.

| Benchmark                     |    0.6.1 |     HEAD | Change |
|:------------------------------|---------:|---------:|-------:|
| vrf_output                    | 77.56 us | 81.38 us |  +4.9% |
| data_to_point_tai             | 20.86 us | 20.72 us |  -0.6% |
| data_to_point_ell2            | 67.43 us | 65.25 us |  -3.2% |
| point_to_hash                 | 634.3 ns | 645.7 ns |  +1.8% |
| challenge                     | 1.147 us | 1.091 us |  -4.9% |
| nonce                         | 2.078 us | 2.050 us |  -1.4% |
| tiny_prove                    | 134.4 us | 134.0 us |  -0.3% |
| tiny_verify                   | 129.7 us | 130.8 us |  +0.9% |
| thin_prove                    | 134.5 us | 135.0 us |  +0.4% |
| thin_verify                   | 120.1 us | 124.5 us |  +3.7% |
| thin batch_verify n=256       | 14.28 ms | 13.82 ms |  -3.3% |
| pedersen_prove                | 374.4 us | 376.1 us |  +0.5% |
| pedersen_verify               | 212.8 us | 213.4 us |  +0.2% |
| pedersen batch_verify n=256   | 15.38 ms | 15.41 ms |  +0.2% |
| ring_prover_key n=1023        | 117.0 ms | 117.6 ms |  +0.6% |
| ring_verifier_key n=1023      | 117.8 ms | 117.8 ms |  +0.1% |
| ring_prove n=1023             | 413.4 ms | 403.1 ms |  -2.5% |
| ring_verify n=1023            | 3.196 ms | 3.183 ms |  -0.4% |
| ring_vk_builder_create n=1023 |  1.382 s |  1.380 s |  -0.2% |
| ring batch_verify n=256       | 84.82 ms | 81.07 ms |  -4.4% |

- `thin_verify` is 3.7% slower, and the ranges of the five runs do not
  overlap. Thin verify now converts the left side of its equation to affine
  form, one field inversion, before it compares it with R. Thus an off-curve
  key or input that gives Z = 0 fails. Tiny verify converted R to affine form
  already: `tiny_verify` moved by +0.9%.
- `batch_push_prepared` (ring) is 8% to 13% faster at all nine batch
  sizes. Its code did not change, and these runs do not show the cause.
- `batch_prepare_par` runs on the rayon pool and moved by -6.2% to +25.6%.
  The ranges of the five runs overlap.
- All other rows are within 8% of 0.6.1, with no trend. The Straus rows,
  whose code did not change, moved by -1.2% to +5.7%: this is the noise
  of the method.
