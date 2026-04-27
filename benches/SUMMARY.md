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
| vrf_output                   | 80.7 us  |
| data_to_point_tai            | 47.6 us  |
| data_to_point_ell2           | 67.4 us  |
| point_to_hash                | 615 ns   |
| challenge                    | 1.13 us  |
| nonce                        | 2.07 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 180.3 us |
| tiny_verify            | 197.9 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 381.5 us |
| pedersen_verify        | 229.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.20 us  | 2.40 us  | 4.82 us  | 11.3 us  | 22.6 us  | 38.3 us  | 76.8 us  | 152.6 us | 311.0 us |
| batch_verify         | 514.0 us | 628.5 us | 726.7 us | 1.65 ms  | 2.22 ms  | 3.65 ms  | 6.33 ms  | 8.60 ms  | 15.5 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 192.1 us |
| thin_verify            | 195.3 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.97 us  | 3.86 us  | 7.45 us  | 16.9 us  | 29.1 us  | 72.1 us  | 126.4 us | 256.4 us | 505.4 us |
| batch_verify         | 480.8 us | 525.0 us | 669.7 us | 1.60 ms  | 2.21 ms  | 3.65 ms  | 6.00 ms  | 7.96 ms  | 14.3 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.86 ms   | 3.74 ms   | 8.43 ms   |
| ring_context_setup     | 0.83 ms   | 3.62 ms   | 8.51 ms   |
| ring_prover_key        | 44.7 ms   | 131.6 ms  | 255.1 ms  |
| ring_verifier_key      | 44.9 ms   | 152.3 ms  | 254.5 ms  |
| ring_prove             | 149.8 ms  | 454.1 ms  | 898.2 ms  |
| ring_verify            | 3.12 ms   | 3.31 ms   | 3.25 ms   |
| ring_verifier_from_key | 249.9 us  | 290.7 us  | 300.6 us  |
| ring_vk_from_commitment| 78.4 ns   | 71.3 ns   | 75.9 ns   |
| ring_vk_builder_create | 321.5 ms  | 1.450 s   | 3.127 s   |
| ring_vk_builder_append | 16.6 ms   | 45.6 ms   | 87.4 ms   |
| ring_vk_builder_finalize | 106.0 ns | 99.0 ns  | 99.5 ns   |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 270.9 us | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 54.0 us  | 103.8 us | 207.9 us | 441.2 us | 876.1 us | 1.78 ms  | 3.58 ms  | 6.76 ms  | 13.40 ms |
| batch_prepare_seq  | 44.5 us  | 87.1 us  | 195.5 us | 386.7 us | 804.1 us | 1.63 ms  | 3.28 ms  | 6.77 ms  | 12.33 ms |
| batch_prepare_par  | 44.3 us  | 76.0 us  | 110.1 us | 155.4 us | 217.5 us | 274.9 us | 235.0 us | 437.5 us | 775.8 us |
| batch_push_prepared| 5.4 us   | 11.0 us  | 18.8 us  | 36.8 us  | 72.2 us  | 141.6 us | 264.9 us | 522.8 us | 1.10 ms  |
| batch_verify       | 3.48 ms  | 4.10 ms  | 6.01 ms  | 8.70 ms  | 12.81 ms | 21.09 ms | 31.58 ms | 54.87 ms | 94.62 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 119.7 us  | 89.7 us   | 94.4 us   | 160.7 us  |
|   3 | 120.5 us  | 109.3 us  | 263.0 us  | 1.53 ms   |
|   4 | 117.9 us  | 204.2 us  | 1.79 ms   | 23.7 ms   |
|   5 | 144.2 us  | 452.2 us  | 11.88 ms  | 539.6 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 150 ms at n=255, 454 ms at n=1023,
  898 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.13 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-110 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.85 ms at n=255,
  ~3.7 ms at n=1023, ~8.5 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (291 us) + n * `ring_verify` (3.31 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~44 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~5.9 ms base + ~0.35 ms per additional
proof. The ring multi-pairing marginal cost is ~0.32 ms/proof; the Pedersen MSM
adds ~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.044 ms (prepare) + ~0.35 ms (verify) = ~0.39 ms,
or ~8.5x cheaper than simple verification (3.31 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.35 ms marginal, or ~9.5x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.60 ms  |    3.52 ms  |    3.52 ms  |         1.02x |         1.02x |
|   2 |    6.91 ms  |    4.19 ms  |    4.18 ms  |         1.65x |         1.65x |
|   4 |   13.53 ms  |    6.21 ms  |    6.12 ms  |         2.18x |         2.21x |
|   8 |   26.77 ms  |    9.09 ms  |    8.86 ms  |         2.95x |         3.02x |
|  16 |   53.25 ms  |   13.62 ms  |   13.03 ms  |         3.91x |         4.09x |
|  32 |  106.21 ms  |   22.72 ms  |   21.36 ms  |         4.67x |         4.97x |
|  64 |  212.13 ms  |   34.86 ms  |   31.81 ms  |         6.09x |         6.67x |
| 128 |  423.97 ms  |   61.64 ms  |   55.31 ms  |         6.88x |         7.66x |
| 256 |  847.65 ms  |  106.95 ms  |   95.40 ms  |         7.92x |         8.88x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.48 ms |  3.48 ms  |
|   2 |    4.10 ms |  2.05 ms  |
|   4 |    6.01 ms |  1.50 ms  |
|   8 |    8.70 ms |  1.09 ms  |
|  16 |   12.81 ms |  0.80 ms  |
|  32 |   21.09 ms |  0.66 ms  |
|  64 |   31.58 ms |  0.49 ms  |
| 128 |   54.87 ms |  0.43 ms  |
| 256 |   94.62 ms |  0.37 ms  |

Amortized cost per proof drops from 3.48 ms (n=1) to 0.37 ms (n=256), roughly 9.4x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.5 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
