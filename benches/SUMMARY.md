# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-09-21
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.10 (crates.io)
Criterion: 0.5.1, `--quick` mode. One run per benchmark, except `ring_prove` and
`ring_verify`, which are medians of four runs.

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
| ring_params_setup        |  849.7 us |  3.646 ms |  7.843 ms |
| ring_context_setup       |  833.9 us |  3.649 ms |  8.304 ms |
| ring_prover_key          |  36.85 ms |  115.2 ms |  212.4 ms |
| ring_verifier_key        |  37.71 ms |  115.9 ms |  215.8 ms |
| ring_keys                |  38.09 ms |  117.2 ms |  214.6 ms |
| ring_prove               |  130.7 ms |  407.0 ms |  741.6 ms |
| ring_verify              |  3.241 ms |  3.255 ms |  3.138 ms |
| ring_verifier_from_key   |  252.3 us |  271.5 us |  283.9 us |
| ring_vk_from_commitment  |  42.26 ns |  42.14 ns |  39.39 ns |
| ring_vk_builder_create   |  306.8 ms |   1.385 s |   2.960 s |
| ring_vk_builder_append   |  13.34 ms |  41.51 ms |  70.20 ms |
| ring_vk_builder_finalize |  76.07 ns |  78.15 ns |  82.57 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 2.147 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 45.75 us | 98.63 us | 197.3 us | 422.7 us | 830.4 us | 1.753 ms | 3.343 ms | 6.692 ms | 13.34 ms |
| batch_prepare_seq  | 42.16 us | 86.89 us | 171.6 us | 389.9 us | 764.7 us | 1.623 ms | 3.127 ms | 6.581 ms | 12.52 ms |
| batch_prepare_par  | 42.04 us | 82.68 us | 122.6 us | 157.2 us | 250.8 us | 263.5 us | 225.0 us | 527.2 us | 871.6 us |
| batch_push_prepared| 4.096 us | 7.388 us | 15.27 us | 31.00 us | 60.07 us | 118.7 us | 238.3 us | 489.8 us | 920.8 us |
| batch_verify       | 3.353 ms | 3.935 ms | 5.443 ms | 7.656 ms | 11.73 ms | 18.18 ms | 30.46 ms | 49.66 ms | 82.87 ms |

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

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 131 ms at n=255, 407 ms at n=1023,
  742 ms at n=2047.
- `ring_keys` costs one indexing pass, the same as either single-key method,
  so a party that needs both keys pays about half of the two calls.
- `ring_vk_builder_create` is the most expensive operation (up to 2.96 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.84 ms at n=255,
  ~3.6 ms at n=1023, ~8.1 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (272 us) + n * `ring_verify` (3.26 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~49 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~8.2 ms base + ~0.30 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.051 ms/proof, leaving ~0.25 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.049 ms (prepare) + ~0.30 ms (verify) = ~0.35 ms,
or ~9.3x cheaper than simple verification (3.26 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.4 us at n=256, giving ~0.30 ms marginal, or ~10.7x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.53 ms  |    3.40 ms  |    3.40 ms  |         1.04x |         1.04x |
|   2 |    6.78 ms  |    4.02 ms  |    4.02 ms  |         1.69x |         1.69x |
|   4 |   13.29 ms  |    5.62 ms  |    5.57 ms  |         2.37x |         2.39x |
|   8 |   26.31 ms  |    8.05 ms  |    7.81 ms  |         3.27x |         3.37x |
|  16 |   52.35 ms  |   12.49 ms  |   11.98 ms  |         4.19x |         4.37x |
|  32 |  104.43 ms  |   19.81 ms  |   18.45 ms  |         5.27x |         5.66x |
|  64 |  208.60 ms  |   33.59 ms  |   30.69 ms  |         6.21x |         6.80x |
| 128 |  416.92 ms  |   56.25 ms  |   50.19 ms  |         7.41x |         8.31x |
| 256 |  833.57 ms  |   95.39 ms  |   83.74 ms  |         8.74x |         9.95x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.35 ms |  3.35 ms  |
|   2 |    3.93 ms |  1.97 ms  |
|   4 |    5.44 ms |  1.36 ms  |
|   8 |    7.66 ms |  0.96 ms  |
|  16 |   11.73 ms |  0.73 ms  |
|  32 |   18.18 ms |  0.57 ms  |
|  64 |   30.46 ms |  0.48 ms  |
| 128 |   49.66 ms |  0.39 ms  |
| 256 |   82.87 ms |  0.32 ms  |

Amortized cost per proof drops from 3.35 ms (n=1) to 0.32 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.8 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
