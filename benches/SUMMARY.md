# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-04-27
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.19.14
- Rust: 1.95.0 (59807616e 2026-04-14)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 80.1 us  |
| data_to_point_tai            | 21.3 us  |
| data_to_point_ell2           | 65.8 us  |
| point_to_hash                | 649 ns   |
| challenge                    | 1.10 us  |
| nonce                        | 2.07 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 185.4 us |
| tiny_verify            | 194.5 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 374.6 us |
| pedersen_verify        | 215.4 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.13 us  | 2.77 us  | 4.78 us  | 9.00 us  | 18.0 us  | 41.0 us  | 76.4 us  | 156.3 us | 305.9 us |
| batch_verify         | 477.6 us | 606.9 us | 740.8 us | 1.66 ms  | 1.99 ms  | 3.59 ms  | 6.17 ms  | 8.45 ms  | 15.1 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 184.8 us |
| thin_verify            | 192.4 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.91 us  | 3.85 us  | 7.65 us  | 15.4 us  | 30.6 us  | 62.8 us  | 127.5 us | 255.1 us | 519.4 us |
| batch_verify         | 475.7 us | 566.5 us | 721.7 us | 1.73 ms  | 2.03 ms  | 3.46 ms  | 5.93 ms  | 8.02 ms  | 14.4 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.99 ms   | 4.61 ms   | 10.07 ms  |
| ring_context_setup     | 1.00 ms   | 4.62 ms   | 9.95 ms   |
| ring_prover_key        | 47.2 ms   | 146.9 ms  | 268.5 ms  |
| ring_verifier_key      | 47.0 ms   | 138.5 ms  | 268.0 ms  |
| ring_prove             | 157.6 ms  | 482.2 ms  | 946.8 ms  |
| ring_verify            | 3.35 ms   | 3.37 ms   | 3.35 ms   |
| ring_verifier_from_key | 299.9 us  | 292.3 us  | 311.3 us  |
| ring_vk_from_commitment| 71.5 ns   | 67.8 ns   | 73.8 ns   |
| ring_vk_builder_create | 337.5 ms  | 1.548 s   | 3.335 s   |
| ring_vk_builder_append | 17.39 ms  | 48.12 ms  | 86.13 ms  |
| ring_vk_builder_finalize | 109.4 ns | 101.3 ns | 101.4 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 2.07 us  | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 49.1 us  | 95.7 us  | 190.3 us | 452.0 us | 888.3 us | 1.71 ms  | 3.82 ms  | 6.84 ms  | 14.28 ms |
| batch_prepare_seq  | 42.8 us  | 85.5 us  | 193.9 us | 398.8 us | 818.1 us | 1.57 ms  | 3.18 ms  | 7.37 ms  | 13.30 ms |
| batch_prepare_par  | 42.9 us  | 76.8 us  | 115.3 us | 163.1 us | 215.9 us | 236.1 us | 223.9 us | 468.9 us | 781.6 us |
| batch_push_prepared| 4.10 us  | 7.86 us  | 15.95 us | 32.00 us | 67.59 us | 128.8 us | 248.1 us | 492.4 us | 1.08 ms  |
| batch_verify       | 3.91 ms  | 4.38 ms  | 5.98 ms  | 8.78 ms  | 15.86 ms | 21.21 ms | 36.57 ms | 58.49 ms | 99.12 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 120.5 us  | 89.0 us   | 95.9 us   | 164.0 us  |
|   3 | 120.6 us  | 107.8 us  | 265.5 us  | 1.64 ms   |
|   4 | 124.6 us  | 178.7 us  | 1.62 ms   | 24.35 ms  |
|   5 | 153.3 us  | 453.2 us  | 13.85 ms  | 515.1 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.35 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 158 ms at n=255, 482 ms at n=1023,
  947 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.34 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-110 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~1.0 ms at n=255,
  ~4.6 ms at n=1023, ~10.0 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (292 us) + n * `ring_verify` (3.37 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~52 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~5.9 ms base + ~0.36 ms per additional
proof. The ring multi-pairing marginal cost is ~0.33 ms/proof; the Pedersen MSM
adds ~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.052 ms (prepare) + ~0.36 ms (verify) = ~0.41 ms,
or ~8.2x cheaper than simple verification (3.37 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.36 ms marginal, or ~9.4x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.66 ms  |    3.95 ms  |    3.95 ms  |         0.93x |         0.93x |
|   2 |    7.03 ms  |    4.47 ms  |    4.46 ms  |         1.57x |         1.58x |
|   4 |   13.77 ms  |    6.17 ms  |    6.10 ms  |         2.23x |         2.26x |
|   8 |   27.25 ms  |    9.18 ms  |    8.94 ms  |         2.97x |         3.05x |
|  16 |   54.21 ms  |   16.68 ms  |   16.08 ms  |         3.25x |         3.37x |
|  32 |  108.13 ms  |   22.78 ms  |   21.45 ms  |         4.75x |         5.04x |
|  64 |  215.97 ms  |   39.75 ms  |   36.79 ms  |         5.43x |         5.87x |
| 128 |  431.65 ms  |   65.86 ms  |   58.96 ms  |         6.55x |         7.32x |
| 256 |  863.01 ms  |  112.42 ms  |   99.90 ms  |         7.68x |         8.64x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.91 ms |  3.91 ms  |
|   2 |    4.38 ms |  2.19 ms  |
|   4 |    5.98 ms |  1.50 ms  |
|   8 |    8.78 ms |  1.10 ms  |
|  16 |   15.86 ms |  0.99 ms  |
|  32 |   21.21 ms |  0.66 ms  |
|  64 |   36.57 ms |  0.57 ms  |
| 128 |   58.49 ms |  0.46 ms  |
| 256 |   99.12 ms |  0.39 ms  |

Amortized cost per proof drops from 3.91 ms (n=1) to 0.39 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.35 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
