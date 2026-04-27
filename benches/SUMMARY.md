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
| ring_params_setup      | 0.87 ms   | 3.93 ms   | 7.84 ms   |
| ring_context_setup     | 0.88 ms   | 3.85 ms   | 8.84 ms   |
| ring_prover_key        | 40.9 ms   | 136.0 ms  | 229.3 ms  |
| ring_verifier_key      | 41.0 ms   | 134.0 ms  | 233.0 ms  |
| ring_prove             | 137.2 ms  | 437.3 ms  | 804.1 ms  |
| ring_verify            | 3.06 ms   | 3.27 ms   | 3.18 ms   |
| ring_verifier_from_key | 270.0 us  | 282.1 us  | 309.8 us  |
| ring_vk_from_commitment| 80.9 ns   | 71.2 ns   | 66.7 ns   |
| ring_vk_builder_create | 317.6 ms  | 1.412 s   | 3.171 s   |
| ring_vk_builder_append | 15.97 ms  | 44.49 ms  | 85.04 ms  |
| ring_vk_builder_finalize | 107.9 ns | 99.0 ns  | 106.3 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 269.8 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 49.0 us  | 95.7 us  | 215.6 us | 444.0 us | 891.6 us | 1.80 ms  | 3.73 ms  | 7.76 ms  | 14.29 ms |
| batch_prepare_seq  | 41.5 us  | 99.6 us  | 184.6 us | 396.5 us | 813.6 us | 1.66 ms  | 3.30 ms  | 6.62 ms  | 13.30 ms |
| batch_prepare_par  | 45.8 us  | 78.7 us  | 114.2 us | 154.2 us | 220.8 us | 252.7 us | 247.9 us | 427.0 us | 787.8 us |
| batch_push_prepared| 4.94 us  | 10.26 us | 17.94 us | 34.85 us | 73.0 us  | 138.4 us | 265.6 us | 536.0 us | 1.08 ms  |
| batch_verify       | 3.24 ms  | 4.62 ms  | 5.85 ms  | 8.91 ms  | 12.51 ms | 21.99 ms | 30.76 ms | 54.37 ms | 96.07 ms |

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

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 137 ms at n=255, 437 ms at n=1023,
  804 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.17 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-110 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.87 ms at n=255,
  ~3.9 ms at n=1023, ~8.3 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (282 us) + n * `ring_verify` (3.27 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~42 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~6.1 ms base + ~0.35 ms per additional
proof. The ring multi-pairing marginal cost is ~0.32 ms/proof; the Pedersen MSM
adds ~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.041 ms (prepare) + ~0.35 ms (verify) = ~0.39 ms,
or ~8.4x cheaper than simple verification (3.27 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.35 ms marginal, or ~9.3x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.55 ms  |    3.28 ms  |    3.29 ms  |         1.08x |         1.08x |
|   2 |    6.82 ms  |    4.72 ms  |    4.70 ms  |         1.44x |         1.45x |
|   4 |   13.36 ms  |    6.04 ms  |    5.96 ms  |         2.21x |         2.24x |
|   8 |   26.44 ms  |    9.31 ms  |    9.07 ms  |         2.84x |         2.92x |
|  16 |   52.60 ms  |   13.32 ms  |   12.73 ms  |         3.95x |         4.13x |
|  32 |  104.92 ms  |   23.65 ms  |   22.24 ms  |         4.43x |         4.72x |
|  64 |  209.56 ms  |   34.06 ms  |   31.01 ms  |         6.15x |         6.76x |
| 128 |  418.84 ms  |   60.99 ms  |   54.80 ms  |         6.87x |         7.64x |
| 256 |  837.40 ms  |  109.37 ms  |   96.86 ms  |         7.66x |         8.65x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.24 ms |  3.24 ms  |
|   2 |    4.62 ms |  2.31 ms  |
|   4 |    5.85 ms |  1.46 ms  |
|   8 |    8.91 ms |  1.11 ms  |
|  16 |   12.51 ms |  0.78 ms  |
|  32 |   21.99 ms |  0.69 ms  |
|  64 |   30.76 ms |  0.48 ms  |
| 128 |   54.37 ms |  0.42 ms  |
| 256 |   96.07 ms |  0.38 ms  |

Amortized cost per proof drops from 3.24 ms (n=1) to 0.38 ms (n=256), roughly 8.5x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.2 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
