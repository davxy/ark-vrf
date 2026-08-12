# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-08-12
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.9
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 7.1.5
- Rust: 1.97.0 (2d8144b78 2026-07-07)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 81.4 us  |
| data_to_point_tai            | 21.1 us  |
| data_to_point_ell2           | 66.5 us  |
| point_to_hash                | 624 ns   |
| challenge                    | 1.10 us  |
| nonce                        | 2.06 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 176.4 us |
| tiny_verify            | 186.5 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 379.7 us |
| pedersen_verify        | 215.9 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.17 us  | 2.63 us  | 5.08 us  | 9.73 us  | 19.5 us  | 38.9 us  | 76.0 us  | 147.7 us | 295.5 us |
| batch_verify         | 501.3 us | 579.4 us | 786.1 us | 1.82 ms  | 2.21 ms  | 3.74 ms  | 6.13 ms  | 8.39 ms  | 15.3 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 172.8 us |
| thin_verify            | 196.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.96 us  | 3.89 us  | 7.75 us  | 15.5 us  | 31.2 us  | 59.9 us  | 121.3 us | 263.9 us | 486.2 us |
| batch_verify         | 492.4 us | 573.1 us | 732.1 us | 1.75 ms  | 2.08 ms  | 3.35 ms  | 5.77 ms  | 7.95 ms  | 14.6 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.79 ms   | 3.82 ms   | 7.93 ms   |
| ring_context_setup     | 0.85 ms   | 3.80 ms   | 8.19 ms   |
| ring_prover_key        | 38.5 ms   | 113.2 ms  | 217.4 ms  |
| ring_verifier_key      | 38.5 ms   | 119.6 ms  | 217.6 ms  |
| ring_prove             | 123.2 ms  | 421.6 ms  | 713.2 ms  |
| ring_verify            | 3.22 ms   | 3.11 ms   | 2.97 ms   |
| ring_verifier_from_key | 249.0 us  | 257.2 us  | 287.6 us  |
| ring_vk_from_commitment| 49.3 ns   | 46.9 ns   | 46.8 ns   |
| ring_vk_builder_create | 308.5 ms  | 1.401 s   | 3.075 s   |
| ring_vk_builder_append | 14.17 ms  | 41.79 ms  | 69.43 ms  |
| ring_vk_builder_finalize | 79.4 ns | 84.9 ns   | 79.1 ns   |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.73 us  | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 47.8 us  | 96.7 us  | 195.7 us | 409.1 us | 840.3 us | 1.68 ms  | 3.54 ms  | 7.57 ms  | 14.05 ms |
| batch_prepare_seq  | 41.9 us  | 88.2 us  | 179.9 us | 390.5 us | 784.6 us | 1.57 ms  | 3.29 ms  | 6.29 ms  | 12.68 ms |
| batch_prepare_par  | 42.1 us  | 80.2 us  | 125.9 us | 181.7 us | 254.6 us | 277.2 us | 184.4 us | 593.0 us | 849.3 us |
| batch_push_prepared| 4.02 us  | 7.64 us  | 14.48 us | 30.31 us | 60.68 us | 121.2 us | 235.1 us | 474.6 us | 934.7 us |
| batch_verify       | 3.34 ms  | 4.04 ms  | 5.14 ms  | 7.55 ms  | 11.05 ms | 18.76 ms | 28.28 ms | 47.48 ms | 85.24 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 114.7 us  | 86.2 us   | 92.7 us   | 158.2 us  |
|   3 | 118.8 us  | 105.3 us  | 264.5 us  | 1.63 ms   |
|   4 | 118.5 us  | 209.8 us  | 1.56 ms   | 27.81 ms  |
|   5 | 133.9 us  | 457.6 us  | 11.96 ms  | 555.6 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.0 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 123 ms at n=255, 422 ms at n=1023,
  713 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.08 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-90 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.8 ms at n=255,
  ~3.8 ms at n=1023, ~8.0 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (257 us) + n * `ring_verify` (3.11 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~49 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.2 ms base + ~0.31 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.05 ms/proof, leaving ~0.26 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.049 ms (prepare) + ~0.31 ms (verify) = ~0.36 ms,
or ~8.7x cheaper than simple verification (3.11 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.3 us at n=256, giving ~0.31 ms marginal, or ~10x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.37 ms  |    3.39 ms  |    3.39 ms  |         0.99x |         0.99x |
|   2 |    6.48 ms  |    4.13 ms  |    4.12 ms  |         1.57x |         1.57x |
|   4 |   12.71 ms  |    5.32 ms  |    5.26 ms  |         2.39x |         2.42x |
|   8 |   25.16 ms  |    7.94 ms  |    7.74 ms  |         3.17x |         3.25x |
|  16 |   50.07 ms  |   11.84 ms  |   11.31 ms  |         4.23x |         4.43x |
|  32 |   99.87 ms  |   20.33 ms  |   19.04 ms  |         4.91x |         5.25x |
|  64 |  199.49 ms  |   31.57 ms  |   28.47 ms  |         6.32x |         7.01x |
| 128 |  398.72 ms  |   53.78 ms  |   48.08 ms  |         7.41x |         8.29x |
| 256 |  797.19 ms  |   97.92 ms  |   86.09 ms  |         8.14x |         9.26x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.34 ms |  3.34 ms  |
|   2 |    4.04 ms |  2.02 ms  |
|   4 |    5.14 ms |  1.28 ms  |
|   8 |    7.55 ms |  0.94 ms  |
|  16 |   11.05 ms |  0.69 ms  |
|  32 |   18.76 ms |  0.59 ms  |
|  64 |   28.28 ms |  0.44 ms  |
| 128 |   47.48 ms |  0.37 ms  |
| 256 |   85.24 ms |  0.33 ms  |

Amortized cost per proof drops from 3.34 ms (n=1) to 0.33 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.0 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
