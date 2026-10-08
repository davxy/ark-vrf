# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-09-21; the Ring VRF sections 2026-09-26 at `f079e25` (ring members
as `Public`), Rust 1.98.1
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.10 (crates.io)
Criterion: 0.5.1, `--quick` mode. One run per benchmark. In the 2026-09-21 run,
`ring_prove` and `ring_verify` were medians of four runs.

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 7.2.6
- Rust: 1.97.1 (8bab26f4f 2026-07-14)

## Common Operations (`common.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| vrf_output             | 78.32 us |
| data_to_point_tai      | 20.98 us |
| data_to_point_ell2     | 65.53 us |
| point_to_hash          | 640.2 ns |
| challenge              | 1.149 us |
| nonce                  | 2.126 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 130.2 us |
| tiny_verify            | 128.5 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 374.5 us |
| pedersen_verify        | 215.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.307 us | 2.478 us | 5.325 us | 10.62 us | 21.22 us | 42.23 us | 84.49 us | 169.2 us | 335.6 us |
| batch_verify         | 523.6 us | 590.1 us | 786.6 us | 1.785 ms | 2.153 ms | 3.642 ms | 6.242 ms | 8.617 ms | 14.58 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 132.5 us |
| thin_verify            | 124.2 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.868 us | 3.538 us | 7.086 us | 14.93 us | 29.88 us | 60.76 us | 123.0 us | 248.7 us | 491.1 us |
| batch_verify         | 470.7 us | 549.5 us | 742.3 us | 1.737 ms | 2.088 ms | 3.540 ms | 5.741 ms | 8.165 ms | 14.56 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  797.1 us |  3.874 ms |  8.311 ms |
| ring_context_setup       |  795.3 us |  3.854 ms |  7.792 ms |
| ring_prover_key          |  40.24 ms |  120.1 ms |  220.7 ms |
| ring_verifier_key        |  36.42 ms |  119.1 ms |  218.5 ms |
| ring_keys                |  39.33 ms |  119.4 ms |  218.8 ms |
| ring_prove               |  132.0 ms |  404.8 ms |  764.3 ms |
| ring_verify              |  3.255 ms |  3.210 ms |  3.353 ms |
| ring_verifier_from_key   |  250.5 us |  271.2 us |  303.7 us |
| ring_vk_from_commitment  |  42.21 ns |  42.47 ns |  42.22 ns |
| ring_vk_builder_create   |  304.6 ms |   1.379 s |   3.081 s |
| ring_vk_builder_append   |  14.17 ms |  41.69 ms |  75.46 ms |
| ring_vk_builder_finalize |  79.85 ns |  79.86 ns |  79.85 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.995 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 46.57 us | 91.54 us | 196.1 us | 405.1 us | 824.9 us | 1.759 ms | 3.558 ms | 6.744 ms | 14.08 ms |
| batch_prepare_seq  | 41.88 us | 89.01 us | 180.1 us | 367.0 us | 761.1 us | 1.633 ms | 3.274 ms | 6.229 ms | 13.14 ms |
| batch_prepare_par  | 44.57 us | 79.33 us | 117.1 us | 174.5 us | 247.3 us | 265.4 us | 203.0 us | 585.1 us | 835.0 us |
| batch_push_prepared| 4.047 us | 7.357 us | 14.60 us | 30.87 us | 63.83 us | 125.3 us | 244.1 us | 505.7 us | 991.1 us |
| batch_verify       | 3.322 ms | 4.159 ms | 5.146 ms | 8.264 ms | 11.45 ms | 18.54 ms | 28.03 ms | 48.91 ms | 86.33 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  113.8 us |  84.90 us |  87.70 us |  159.0 us |
|   3 |  116.1 us |  99.90 us |  248.7 us |  1.535 ms |
|   4 |  113.1 us |  178.7 us |  1.618 ms |  24.87 ms |
|   5 |  126.5 us |  471.0 us |  12.64 ms |  429.0 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.3 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 132 ms at n=255, 405 ms at n=1023,
  764 ms at n=2047.
- `ring_keys` costs one indexing pass, the same as either single-key method,
  so a party that needs both keys pays about half of the two calls.
- Taking the ring members as `Public` keys (one extra copy of the points)
  changes no key row beyond the run-to-run noise: rows that the change does
  not touch, such as `ring_params_setup` and `ring_vk_builder_create`, moved
  by up to 6% between the two runs too.
- `ring_vk_builder_create` is the most expensive operation (up to 3.08 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.80 ms at n=255,
  ~3.9 ms at n=1023, ~8.1 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (271 us) + n * `ring_verify` (3.21 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~51 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.3 ms base + ~0.31 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.051 ms/proof, leaving ~0.26 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.051 ms (prepare) + ~0.31 ms (verify) = ~0.36 ms,
or ~8.9x cheaper than simple verification (3.21 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.3 us at n=256, giving ~0.32 ms marginal, or ~10.2x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.48 ms  |    3.36 ms  |    3.37 ms  |         1.03x |         1.03x |
|   2 |    6.69 ms  |    4.25 ms  |    4.24 ms  |         1.58x |         1.58x |
|   4 |   13.11 ms  |    5.33 ms  |    5.26 ms  |         2.46x |         2.49x |
|   8 |   25.95 ms  |    8.63 ms  |    8.44 ms  |         3.01x |         3.08x |
|  16 |   51.63 ms  |   12.21 ms  |   11.70 ms  |         4.23x |         4.41x |
|  32 |  102.98 ms  |   20.18 ms  |   18.81 ms  |         5.10x |         5.48x |
|  64 |  205.70 ms  |   31.31 ms  |   28.24 ms  |         6.57x |         7.28x |
| 128 |  411.13 ms  |   55.14 ms  |   49.49 ms  |         7.46x |         8.31x |
| 256 |  821.98 ms  |   99.47 ms  |   87.17 ms  |         8.26x |         9.43x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.32 ms |  3.32 ms  |
|   2 |    4.16 ms |  2.08 ms  |
|   4 |    5.15 ms |  1.29 ms  |
|   8 |    8.26 ms |  1.03 ms  |
|  16 |   11.45 ms |  0.72 ms  |
|  32 |   18.54 ms |  0.58 ms  |
|  64 |   28.03 ms |  0.44 ms  |
| 128 |   48.91 ms |  0.38 ms  |
| 256 |   86.33 ms |  0.34 ms  |

Amortized cost per proof drops from 3.32 ms (n=1) to 0.34 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.8 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
