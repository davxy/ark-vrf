# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-11-05, at `6fc4971`
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
| vrf_output             | 77.19 us |
| data_to_point_tai      | 21.85 us |
| data_to_point_ell2     | 64.93 us |
| point_to_hash          | 643.2 ns |
| challenge              | 1.108 us |
| nonce                  | 2.021 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 135.7 us |
| tiny_verify            | 128.8 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 376.5 us |
| pedersen_verify        | 211.2 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.238 us | 2.404 us | 4.981 us | 9.952 us | 19.73 us | 39.47 us | 78.67 us | 157.5 us | 315.1 us |
| batch_verify         | 523.5 us | 617.0 us | 781.4 us | 1.804 ms | 2.171 ms | 3.681 ms | 6.308 ms | 8.564 ms | 15.34 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 134.5 us |
| thin_verify            | 117.4 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.941 us | 3.872 us | 7.675 us | 14.68 us | 30.51 us | 63.09 us | 127.0 us | 253.9 us | 508.1 us |
| batch_verify         | 482.7 us | 557.7 us | 672.1 us | 1.698 ms | 2.021 ms | 3.440 ms | 5.876 ms | 7.848 ms | 14.11 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  793.0 us |  3.845 ms |  8.287 ms |
| ring_context_setup       |  788.5 us |  3.837 ms |  8.239 ms |
| ring_prover_key          |  37.91 ms |  117.6 ms |  215.3 ms |
| ring_verifier_key        |  37.76 ms |  117.6 ms |  215.0 ms |
| ring_keys                |  37.75 ms |  117.0 ms |  215.2 ms |
| ring_prove               |  127.8 ms |  393.7 ms |  740.5 ms |
| ring_verify              |  3.231 ms |  3.207 ms |  3.240 ms |
| ring_verifier_from_key   |  254.0 us |  275.5 us |  303.6 us |
| ring_vk_from_commitment  |  47.19 ns |  47.26 ns |  47.54 ns |
| ring_vk_builder_create   |  291.5 ms |   1.382 s |   3.005 s |
| ring_vk_builder_append   |  13.09 ms |  41.06 ms |  72.48 ms |
| ring_vk_builder_finalize |  79.50 ns |  79.81 ns |  79.54 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.913 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 43.95 us | 92.99 us | 180.4 us | 409.9 us | 844.5 us | 1.714 ms | 3.282 ms | 6.833 ms | 12.92 ms |
| batch_prepare_seq  | 43.18 us | 92.00 us | 187.5 us | 405.5 us | 834.9 us | 1.603 ms | 3.250 ms | 6.855 ms | 12.86 ms |
| batch_prepare_par  | 43.50 us | 80.12 us | 128.5 us | 184.8 us | 270.9 us | 270.6 us | 428.8 us | 726.2 us | 1.087 ms |
| batch_push_prepared| 706.7 ns | 1.160 us | 2.493 us | 4.937 us | 9.950 us | 19.68 us | 37.81 us | 76.90 us | 144.7 us |
| batch_verify       | 3.154 ms | 3.840 ms | 5.377 ms | 7.818 ms | 10.72 ms | 17.37 ms | 27.55 ms | 48.40 ms | 84.45 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  112.4 us |  85.60 us |  94.13 us |  164.3 us |
|   3 |  114.2 us |  104.5 us |  271.5 us |  1.683 ms |
|   4 |  117.7 us |  178.5 us |  1.697 ms |  24.47 ms |
|   5 |  124.7 us |  488.8 us |  12.75 ms |  511.2 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 128 ms at n=255, 394 ms at n=1023,
  741 ms at n=2047.
- `ring_keys` costs one indexing pass, the same as either single-key method,
  so a party that needs both keys pays about half of the two calls.
- `ring_vk_builder_create` is the most expensive operation (up to 3.01 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.79 ms at n=255,
  ~3.8 ms at n=1023, ~8.3 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (276 us) + n * `ring_verify` (3.21 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~50 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~6.8 ms base + ~0.31 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.054 ms/proof, leaving ~0.25 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.050 ms (prepare) + ~0.308 ms (verify) = ~0.358 ms,
or ~8.9x cheaper than simple verification (3.21 ms). With parallel prepare, the
per-proof prepare cost drops to ~4.2 us at n=256, giving ~0.31 ms marginal, or ~10.3x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.48 ms  |    3.20 ms  |    3.20 ms  |         1.09x |         1.09x |
|   2 |    6.69 ms  |    3.93 ms  |    3.92 ms  |         1.70x |         1.71x |
|   4 |   13.10 ms  |    5.56 ms  |    5.51 ms  |         2.35x |         2.38x |
|   8 |   25.93 ms  |    8.22 ms  |    8.00 ms  |         3.15x |         3.24x |
|  16 |   51.58 ms  |   11.56 ms  |   10.99 ms  |         4.46x |         4.69x |
|  32 |  102.88 ms  |   18.98 ms  |   17.64 ms  |         5.42x |         5.83x |
|  64 |  205.49 ms  |   30.80 ms  |   27.98 ms  |         6.67x |         7.34x |
| 128 |  410.71 ms  |   55.26 ms  |   49.13 ms  |         7.43x |         8.36x |
| 256 |  821.14 ms  |   97.31 ms  |   85.53 ms  |         8.44x |         9.60x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.15 ms |  3.15 ms  |
|   2 |    3.84 ms |  1.92 ms  |
|   4 |    5.38 ms |  1.34 ms  |
|   8 |    7.82 ms |  0.98 ms  |
|  16 |   10.72 ms |  0.67 ms  |
|  32 |   17.37 ms |  0.54 ms  |
|  64 |   27.55 ms |  0.43 ms  |
| 128 |   48.40 ms |  0.38 ms  |
| 256 |   84.45 ms |  0.33 ms  |

Amortized cost per proof drops from 3.15 ms (n=1) to 0.33 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.6 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).

## Comparison with 0.6.1

The `v0.6.1` tag ran on the same machine and day as the tables above, with
the same lock file, so all dependencies have the same versions. The two
versions alternated for each bench binary, five times. The values are the
medians of the five runs.

| Benchmark                     |    0.6.1 |     HEAD | Change |
|:------------------------------|---------:|---------:|-------:|
| vrf_output                    | 81.01 us | 77.19 us |  -4.7% |
| data_to_point_tai             | 21.88 us | 21.85 us |  -0.1% |
| data_to_point_ell2            | 67.66 us | 64.93 us |  -4.0% |
| point_to_hash                 | 647.7 ns | 643.2 ns |  -0.7% |
| challenge                     | 1.154 us | 1.108 us |  -4.0% |
| nonce                         | 2.154 us | 2.021 us |  -6.2% |
| tiny_prove                    | 134.1 us | 135.7 us |  +1.2% |
| tiny_verify                   | 129.7 us | 128.8 us |  -0.7% |
| thin_prove                    | 133.6 us | 134.5 us |  +0.7% |
| thin_verify                   | 119.6 us | 117.4 us |  -1.9% |
| thin batch_verify n=256       | 14.54 ms | 14.11 ms |  -2.9% |
| pedersen_prove                | 374.5 us | 376.5 us |  +0.5% |
| pedersen_verify               | 210.7 us | 211.2 us |  +0.2% |
| pedersen batch_verify n=256   | 15.24 ms | 15.34 ms |  +0.7% |
| ring_prover_key n=1023        | 118.6 ms | 117.6 ms |  -0.9% |
| ring_verifier_key n=1023      | 117.5 ms | 117.6 ms |  +0.1% |
| ring_prove n=1023             | 406.6 ms | 393.7 ms |  -3.2% |
| ring_verify n=1023            | 3.178 ms | 3.207 ms |  +0.9% |
| ring_vk_builder_create n=1023 |  1.373 s |  1.382 s |  +0.6% |
| ring batch_verify n=256       | 84.88 ms | 84.45 ms |  -0.5% |

- `thin_verify` moved by -1.9% and `tiny_verify` by -0.7%, and the ranges of the
  five runs overlap. Since 0.6.1 both verifiers reject a value with Z = 0,
  which an off-curve key or input from the unchecked path can give. The
  check reads Z and has no measurable cost.
- `batch_push_prepared` (ring) is 3% to 10% faster at all nine batch
  sizes, but the ranges of the five runs overlap. Its code did not change.
- `batch_prepare_par` runs on the rayon pool and moved by -8.1% to +20.3%.
  The ranges of the five runs overlap.
- All other rows are within 9% of 0.6.1. The Straus rows, whose code
  did not change, moved by -5.2% to +5.6%: this is the noise of the
  method.
