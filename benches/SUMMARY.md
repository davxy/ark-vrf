# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-08-14
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Backend: `w3f-ring-proof` 0.0.10 (git rev `59f65b77`)
Criterion: `--quick` mode. One run per benchmark, except `ring_prove` and
`ring_verify`, which are medians of four runs.

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 7.1.5
- Rust: 1.97.1 (8bab26f4f 2026-07-14)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 79.7 us  |
| data_to_point_tai            | 21.1 us  |
| data_to_point_ell2           | 65.7 us  |
| point_to_hash                | 595 ns   |
| challenge                    | 1.12 us  |
| nonce                        | 2.02 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 186.4 us |
| tiny_verify            | 192.3 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 379.8 us |
| pedersen_verify        | 210.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.21 us  | 2.41 us  | 4.87 us  | 9.29 us  | 19.7 us  | 36.7 us  | 73.5 us  | 158.2 us | 308.7 us |
| batch_verify         | 529.4 us | 606.1 us | 774.7 us | 1.72 ms  | 2.09 ms  | 3.52 ms  | 6.04 ms  | 8.53 ms  | 15.6 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 182.0 us |
| thin_verify            | 187.8 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.87 us  | 3.74 us  | 7.47 us  | 14.2 us  | 28.7 us  | 58.3 us  | 116.9 us | 234.1 us | 497.8 us |
| batch_verify         | 503.5 us | 574.6 us | 730.1 us | 1.68 ms  | 2.00 ms  | 3.40 ms  | 5.81 ms  | 7.77 ms  | 14.3 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.84 ms   | 3.73 ms   | 8.32 ms   |
| ring_context_setup     | 0.84 ms   | 3.78 ms   | 8.28 ms   |
| ring_prover_key        | 39.0 ms   | 125.7 ms  | 219.7 ms  |
| ring_verifier_key      | 38.9 ms   | 116.2 ms  | 209.9 ms  |
| ring_prove             | 132.8 ms  | 418.8 ms  | 782.0 ms  |
| ring_verify            | 3.24 ms   | 3.24 ms   | 3.23 ms   |
| ring_verifier_from_key | 244.0 us  | 262.8 us  | 301.3 us  |
| ring_vk_from_commitment| 47.4 ns   | 47.4 ns   | 49.4 ns   |
| ring_vk_builder_create | 316.9 ms  | 1.529 s   | 3.329 s   |
| ring_vk_builder_append | 17.95 ms  | 42.27 ms  | 83.45 ms  |
| ring_vk_builder_finalize | 78.7 ns | 82.2 ns   | 85.4 ns   |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.71 us  | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 45.8 us  | 96.3 us  | 198.1 us | 421.4 us | 902.0 us | 1.75 ms  | 3.39 ms  | 6.80 ms  | 13.44 ms |
| batch_prepare_seq  | 42.1 us  | 88.7 us  | 181.1 us | 368.7 us | 765.8 us | 1.55 ms  | 3.11 ms  | 6.70 ms  | 12.46 ms |
| batch_prepare_par  | 42.4 us  | 80.1 us  | 117.2 us | 183.4 us | 241.9 us | 255.7 us | 210.9 us | 451.6 us | 840.4 us |
| batch_push_prepared| 3.86 us  | 7.89 us  | 14.56 us | 31.59 us | 60.68 us | 120.2 us | 237.9 us | 506.0 us | 929.7 us |
| batch_verify       | 3.35 ms  | 3.91 ms  | 5.26 ms  | 7.76 ms  | 11.09 ms | 18.94 ms | 28.46 ms | 49.66 ms | 84.04 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 130.0 us  | 96.7 us   | 100.2 us  | 164.6 us  |
|   3 | 132.2 us  | 112.5 us  | 269.1 us  | 1.62 ms   |
|   4 | 135.4 us  | 183.1 us  | 1.63 ms   | 25.24 ms  |
|   5 | 137.1 us  | 466.6 us  | 12.69 ms  | 427.6 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 133 ms at n=255, 419 ms at n=1023,
  782 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.33 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-90 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.84 ms at n=255,
  ~3.8 ms at n=1023, ~8.3 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (263 us) + n * `ring_verify` (3.24 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~49 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.7 ms base + ~0.31 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.055 ms/proof, leaving ~0.25 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.049 ms (prepare) + ~0.31 ms (verify) = ~0.35 ms,
or ~9.2x cheaper than simple verification (3.24 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.3 us at n=256, giving ~0.31 ms marginal, or ~10.5x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.50 ms  |    3.40 ms  |    3.40 ms  |         1.03x |         1.03x |
|   2 |    6.74 ms  |    4.01 ms  |    4.00 ms  |         1.68x |         1.68x |
|   4 |   13.22 ms  |    5.46 ms  |    5.40 ms  |         2.42x |         2.45x |
|   8 |   26.18 ms  |    8.16 ms  |    7.98 ms  |         3.21x |         3.28x |
|  16 |   52.10 ms  |   11.91 ms  |   11.39 ms  |         4.37x |         4.57x |
|  32 |  103.94 ms  |   20.61 ms  |   19.32 ms  |         5.04x |         5.38x |
|  64 |  207.62 ms  |   31.81 ms  |   28.91 ms  |         6.53x |         7.18x |
| 128 |  414.98 ms  |   56.86 ms  |   50.61 ms  |         7.30x |         8.20x |
| 256 |  829.70 ms  |   97.43 ms  |   85.81 ms  |         8.52x |         9.67x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.35 ms |  3.35 ms  |
|   2 |    3.91 ms |  1.96 ms  |
|   4 |    5.26 ms |  1.32 ms  |
|   8 |    7.76 ms |  0.97 ms  |
|  16 |   11.09 ms |  0.69 ms  |
|  32 |   18.94 ms |  0.59 ms  |
|  64 |   28.46 ms |  0.44 ms  |
| 128 |   49.66 ms |  0.39 ms  |
| 256 |   84.04 ms |  0.33 ms  |

Amortized cost per proof drops from 3.35 ms (n=1) to 0.33 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.0 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
