# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-10-20, at `f9a9133`
Features: `full`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.10 (crates.io)
Criterion: 0.5.1, `--quick` mode. Each value is the median of five runs.

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 7.2.11
- Rust: 1.98.1 (48a229cea 2026-09-01)

## Common Operations (`common.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| vrf_output             | 81.78 us |
| data_to_point_tai      | 21.89 us |
| data_to_point_ell2     | 67.64 us |
| point_to_hash          | 646.2 ns |
| challenge              | 1.144 us |
| nonce                  | 2.140 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 133.8 us |
| tiny_verify            | 129.6 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 376.2 us |
| pedersen_verify        | 213.3 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.239 us | 2.486 us | 4.910 us | 9.936 us | 18.83 us | 37.74 us | 78.87 us | 150.5 us | 302.0 us |
| batch_verify         | 525.7 us | 596.9 us | 780.4 us | 1.776 ms | 2.079 ms | 3.663 ms | 6.009 ms | 8.209 ms | 15.25 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 135.6 us |
| thin_verify            | 120.0 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.912 us | 3.812 us | 7.644 us | 15.27 us | 30.37 us | 61.88 us | 119.1 us | 239.0 us | 476.8 us |
| batch_verify         | 492.9 us | 568.9 us | 717.0 us | 1.741 ms | 2.063 ms | 3.499 ms | 5.732 ms | 7.955 ms | 14.30 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  798.2 us |  3.850 ms |  7.777 ms |
| ring_context_setup       |  836.6 us |  3.845 ms |  7.816 ms |
| ring_prover_key          |  38.45 ms |  119.0 ms |  217.8 ms |
| ring_verifier_key        |  38.33 ms |  119.3 ms |  217.5 ms |
| ring_keys                |  38.30 ms |  119.0 ms |  217.3 ms |
| ring_prove               |  130.2 ms |  403.6 ms |  757.0 ms |
| ring_verify              |  3.130 ms |  2.983 ms |  2.981 ms |
| ring_verifier_from_key   |  254.8 us |  279.3 us |  304.5 us |
| ring_vk_from_commitment  |  41.53 ns |  39.68 ns |  41.22 ns |
| ring_vk_builder_create   |  304.5 ms |   1.360 s |   2.947 s |
| ring_vk_builder_append   |  14.07 ms |  41.35 ms |  70.23 ms |
| ring_vk_builder_finalize |  79.55 ns |  75.62 ns |  75.25 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.990 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 45.29 us | 96.31 us | 185.0 us | 399.1 us | 823.4 us | 1.740 ms | 3.315 ms | 6.940 ms | 13.20 ms |
| batch_prepare_seq  | 41.57 us | 87.88 us | 169.7 us | 365.5 us | 796.7 us | 1.611 ms | 3.237 ms | 6.190 ms | 12.32 ms |
| batch_prepare_par  | 41.52 us | 78.47 us | 119.6 us | 175.1 us | 241.6 us | 248.9 us | 201.1 us | 466.6 us | 866.9 us |
| batch_push_prepared| 4.087 us | 7.429 us | 14.75 us | 31.87 us | 63.66 us | 121.2 us | 236.7 us | 471.3 us | 927.7 us |
| batch_verify       | 3.127 ms | 3.840 ms | 5.083 ms | 7.449 ms | 11.36 ms | 17.53 ms | 27.93 ms | 46.40 ms | 82.11 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  111.6 us |  85.79 us |  94.69 us |  163.9 us |
|   3 |  114.5 us |  104.8 us |  271.5 us |  1.682 ms |
|   4 |  117.3 us |  180.6 us |  1.657 ms |  25.42 ms |
|   5 |  123.9 us |  488.7 us |  12.73 ms |  417.1 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.0 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 130 ms at n=255, 404 ms at n=1023,
  757 ms at n=2047.
- `ring_keys` costs one indexing pass, the same as either single-key method,
  so a party that needs both keys pays about half of the two calls.
- Taking the ring members as `Public` keys (one extra copy of the points)
  does not change the key rows: `ring_prover_key` and `ring_verifier_key`
  are within 1% of 0.5.3.
- `ring_vk_builder_create` is the most expensive operation (up to 2.95 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.82 ms at n=255,
  ~3.8 ms at n=1023, ~7.8 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (279 us) + n * `ring_verify` (2.98 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~48 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.2 ms base + ~0.30 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.053 ms/proof, leaving ~0.24 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.048 ms (prepare) + ~0.297 ms (verify) = ~0.345 ms,
or ~8.7x cheaper than simple verification (2.98 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.4 us at n=256, giving ~0.30 ms marginal, or ~9.9x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.26 ms  |    3.17 ms  |    3.17 ms  |         1.03x |         1.03x |
|   2 |    6.25 ms  |    3.93 ms  |    3.92 ms  |         1.59x |         1.59x |
|   4 |   12.21 ms  |    5.25 ms  |    5.20 ms  |         2.33x |         2.35x |
|   8 |   24.14 ms  |    7.81 ms  |    7.62 ms  |         3.09x |         3.17x |
|  16 |   48.01 ms  |   12.16 ms  |   11.60 ms  |         3.95x |         4.14x |
|  32 |   95.74 ms  |   19.14 ms  |   17.78 ms  |         5.00x |         5.38x |
|  64 |  191.20 ms  |   31.16 ms  |   28.13 ms  |         6.14x |         6.80x |
| 128 |  382.13 ms  |   52.59 ms  |   46.87 ms  |         7.27x |         8.15x |
| 256 |  763.98 ms  |   94.43 ms  |   82.98 ms  |         8.09x |         9.21x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.13 ms |  3.13 ms  |
|   2 |    3.84 ms |  1.92 ms  |
|   4 |    5.08 ms |  1.27 ms  |
|   8 |    7.45 ms |  0.93 ms  |
|  16 |   11.36 ms |  0.71 ms  |
|  32 |   17.53 ms |  0.55 ms  |
|  64 |   27.93 ms |  0.44 ms  |
| 128 |   46.40 ms |  0.36 ms  |
| 256 |   82.11 ms |  0.32 ms  |

Amortized cost per proof drops from 3.13 ms (n=1) to 0.32 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.6 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).

## Comparison with 0.5.3

The `v0.5.3` tag ran on the same machine and day as the tables above, with
the same lock file, so all dependencies have the same versions. The two
versions alternated for each bench binary, five times. The values are the
medians of the five runs.

| Benchmark                     |    0.5.3 |    0.6.0 | Change |
|:------------------------------|---------:|---------:|-------:|
| vrf_output                    | 82.75 us | 81.78 us |  -1.2% |
| data_to_point_tai             | 20.92 us | 21.89 us |  +4.6% |
| data_to_point_ell2            | 65.55 us | 67.64 us |  +3.2% |
| point_to_hash                 | 618.7 ns | 646.2 ns |  +4.4% |
| challenge                     | 1.123 us | 1.144 us |  +1.9% |
| nonce                         | 2.085 us | 2.140 us |  +2.6% |
| tiny_prove                    | 179.5 us | 133.8 us | -25.5% |
| tiny_verify                   | 188.6 us | 129.6 us | -31.3% |
| thin_prove                    | 181.6 us | 135.6 us | -25.3% |
| thin_verify                   | 186.4 us | 120.0 us | -35.6% |
| thin batch_verify n=256       | 14.18 ms | 14.30 ms |  +0.9% |
| pedersen_prove                | 388.4 us | 376.2 us |  -3.2% |
| pedersen_verify               | 219.2 us | 213.3 us |  -2.7% |
| pedersen batch_verify n=256   | 15.91 ms | 15.25 ms |  -4.2% |
| ring_prover_key n=1023        | 119.1 ms | 119.0 ms |  -0.1% |
| ring_verifier_key n=1023      | 118.9 ms | 119.3 ms |  +0.3% |
| ring_prove n=1023             | 408.4 ms | 403.6 ms |  -1.2% |
| ring_verify n=1023            | 3.051 ms | 2.983 ms |  -2.2% |
| ring_vk_builder_create n=1023 |  1.368 s |  1.360 s |  -0.6% |
| ring batch_verify n=256       | 82.68 ms | 82.11 ms |  -0.7% |

- Tiny and Thin with one I/O pair are 25% to 36% faster. Verification runs
  one Straus pass over the four raw points, and the provers merge only the
  inputs.
- `data_to_point_tai`, `point_to_hash`, `nonce` and `challenge` are 2% to 5%
  slower. Since 0.6.0 the transcript reader zeroizes its seed and its output
  block on drop. A copy of 0.6.0 without this zeroization measured within
  1.5% of 0.5.3 on these four rows.
- Pedersen `batch_verify` is 2% to 8% faster at all nine batch sizes. The
  ranges of the five runs overlap, and these runs do not show the cause.
- All other rows are within 9% of 0.5.3, with no trend. The Straus rows,
  whose code did not change, moved by -2.2% to +4.4%: this is the noise
  of the method.
- `ring_keys` is new in 0.6.0.
