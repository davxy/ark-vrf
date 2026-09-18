# Benchmark Baseline

Suite: `Bandersnatch-SHA512-ELL2-v1` (Twisted Edwards on BLS12-381)
Date: 2026-09-18
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
| vrf_output             | 77.72 us |
| data_to_point_tai      | 20.85 us |
| data_to_point_ell2     | 64.90 us |
| point_to_hash          |   625 ns |
| challenge              |  1.14 us |
| nonce                  |  2.11 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 174.0 us |
| tiny_verify            | 184.2 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 371.6 us |
| pedersen_verify        | 205.7 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.19 us  | 2.54 us  | 5.05 us  | 10.04 us | 20.17 us | 47.64 us | 76.28 us | 155.8 us | 305.7 us |
| batch_verify         | 510.2 us | 605.1 us | 773.1 us | 1.76 ms  | 2.12 ms  | 3.60 ms  | 6.25 ms  | 8.05 ms  | 14.62 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 182.1 us |
| thin_verify            | 187.3 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.96 us  | 3.92 us  | 7.68 us  | 14.82 us | 29.70 us | 60.10 us | 133.0 us | 243.1 us | 486.2 us |
| batch_verify         | 477.0 us | 551.7 us | 671.7 us | 1.61 ms  | 1.92 ms  | 3.28 ms  | 5.58 ms  | 7.53 ms  | 14.68 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  794.8 us |   3.67 ms |   7.65 ms |
| ring_context_setup       |  793.0 us |   3.95 ms |   7.84 ms |
| ring_prover_key          |  37.06 ms |  116.5 ms |  205.6 ms |
| ring_verifier_key        |  37.13 ms |  115.1 ms |  207.9 ms |
| ring_prove               |  122.7 ms |  411.5 ms |  721.9 ms |
| ring_verify              |   3.06 ms |   3.19 ms |   3.10 ms |
| ring_verifier_from_key   |  253.6 us |  272.3 us |  289.7 us |
| ring_vk_from_commitment  |   44.8 ns |   47.4 ns |   45.0 ns |
| ring_vk_builder_create   |  287.1 ms |   1.348 s |   3.058 s |
| ring_vk_builder_append   |  13.62 ms |  41.82 ms |  70.43 ms |
| ring_vk_builder_finalize |   74.8 ns |   74.6 ns |   79.3 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 2.00 us  | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 46.31 us | 92.19 us | 185.9 us | 428.6 us | 830.8 us | 1.69 ms  | 3.53 ms  | 6.75 ms  | 14.20 ms |
| batch_prepare_seq  | 42.23 us | 84.66 us | 180.6 us | 388.5 us | 784.0 us | 1.65 ms  | 3.27 ms  | 6.26 ms  | 12.95 ms |
| batch_prepare_par  | 42.14 us | 79.33 us | 121.0 us | 177.8 us | 239.1 us | 259.9 us | 204.4 us | 525.3 us | 819.2 us |
| batch_push_prepared| 3.87 us  | 7.74 us  | 15.04 us | 31.50 us | 60.03 us | 119.3 us | 235.3 us | 475.4 us | 926.2 us |
| batch_verify       | 3.16 ms  | 4.06 ms  | 5.45 ms  | 7.75 ms  | 11.02 ms | 17.95 ms | 28.52 ms | 49.09 ms | 83.41 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  108.2 us |  87.54 us |  93.18 us |  161.1 us |
|   3 |  115.4 us |  104.6 us |  265.7 us |   1.63 ms |
|   4 |  119.8 us |  175.2 us |   1.63 ms |  25.19 ms |
|   5 |  121.1 us |  471.9 us |  12.45 ms |  431.9 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.1 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 123 ms at n=255, 412 ms at n=1023,
  722 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.06 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.79 ms at n=255,
  ~3.7 ms at n=1023, ~7.6 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (272 us) + n * `ring_verify` (3.19 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~51 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.5 ms base + ~0.30 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.051 ms/proof, leaving ~0.25 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.051 ms (prepare) + ~0.30 ms (verify) = ~0.35 ms,
or ~9.0x cheaper than simple verification (3.19 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.2 us at n=256, giving ~0.31 ms marginal, or ~10.4x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.47 ms  |    3.20 ms  |    3.20 ms  |         1.08x |         1.08x |
|   2 |    6.66 ms  |    4.14 ms  |    4.14 ms  |         1.61x |         1.61x |
|   4 |   13.05 ms  |    5.63 ms  |    5.57 ms  |         2.32x |         2.34x |
|   8 |   25.82 ms  |    8.14 ms  |    7.93 ms  |         3.17x |         3.26x |
|  16 |   51.37 ms  |   11.80 ms  |   11.26 ms  |         4.35x |         4.56x |
|  32 |  102.47 ms  |   19.59 ms  |   18.20 ms  |         5.23x |         5.63x |
|  64 |  204.66 ms  |   31.79 ms  |   28.72 ms  |         6.44x |         7.13x |
| 128 |  409.05 ms  |   55.35 ms  |   49.61 ms  |         7.39x |         8.24x |
| 256 |  817.83 ms  |   96.36 ms  |   84.23 ms  |         8.49x |         9.71x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.16 ms |  3.16 ms  |
|   2 |    4.06 ms |  2.03 ms  |
|   4 |    5.45 ms |  1.36 ms  |
|   8 |    7.75 ms |  0.97 ms  |
|  16 |   11.02 ms |  0.69 ms  |
|  32 |   17.95 ms |  0.56 ms  |
|  64 |   28.52 ms |  0.45 ms  |
| 128 |   49.09 ms |  0.38 ms  |
| 256 |   83.41 ms |  0.33 ms  |

Amortized cost per proof drops from 3.16 ms (n=1) to 0.33 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.7 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
