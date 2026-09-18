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
| vrf_output             | 76.05 us |
| data_to_point_tai      | 20.99 us |
| data_to_point_ell2     | 66.04 us |
| point_to_hash          |   628 ns |
| challenge              |  1.12 us |
| nonce                  |  2.10 us |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 183.4 us |
| tiny_verify            | 195.9 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 353.9 us |
| pedersen_verify        | 216.2 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.15 us  | 2.43 us  | 4.87 us  | 9.73 us  | 19.43 us | 39.49 us | 77.21 us | 154.3 us | 308.8 us |
| batch_verify         | 526.7 us | 607.6 us | 774.4 us | 1.79 ms  | 2.17 ms  | 3.66 ms  | 6.25 ms  | 8.55 ms  | 15.43 ms |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 182.6 us |
| thin_verify            | 185.3 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.84 us  | 3.68 us  | 7.36 us  | 14.72 us | 30.41 us | 58.67 us | 114.1 us | 228.7 us | 487.5 us |
| batch_verify         | 477.0 us | 554.0 us | 708.1 us | 1.69 ms  | 2.03 ms  | 3.23 ms  | 5.60 ms  | 7.48 ms  | 14.20 ms |

## Ring VRF Operations (`ring.rs`)

| Benchmark                | n=255     | n=1023    | n=2047    |
|:-------------------------|----------:|----------:|----------:|
| ring_params_setup        |  847.4 us |   3.84 ms |   7.64 ms |
| ring_context_setup       |  835.5 us |   3.82 ms |   8.35 ms |
| ring_prover_key          |  38.57 ms |  119.7 ms |  216.1 ms |
| ring_verifier_key        |  36.73 ms |  113.2 ms |  207.1 ms |
| ring_prove               |  128.1 ms |  403.6 ms |  735.0 ms |
| ring_verify              |   3.20 ms |   3.01 ms |   3.13 ms |
| ring_verifier_from_key   |  252.0 us |  259.4 us |  301.4 us |
| ring_vk_from_commitment  |   49.4 ns |   46.9 ns |   46.6 ns |
| ring_vk_builder_create   |  298.6 ms |   1.381 s |   2.983 s |
| ring_vk_builder_append   |  13.30 ms |  38.83 ms |  70.44 ms |
| ring_vk_builder_finalize |   80.5 ns |   79.7 ns |   74.6 ns |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 1.88 us  | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 45.55 us | 91.17 us | 203.1 us | 399.5 us | 862.0 us | 1.66 ms  | 3.50 ms  | 7.04 ms  | 13.86 ms |
| batch_prepare_seq  | 41.65 us | 90.06 us | 171.2 us | 366.1 us | 798.0 us | 1.63 ms  | 3.22 ms  | 6.17 ms  | 12.33 ms |
| batch_prepare_par  | 41.83 us | 80.96 us | 121.7 us | 175.1 us | 239.4 us | 250.7 us | 201.0 us | 511.5 us | 837.1 us |
| batch_push_prepared| 3.93 us  | 7.53 us  | 14.65 us | 31.86 us | 60.92 us | 119.6 us | 238.3 us | 471.0 us | 930.9 us |
| batch_verify       | 3.36 ms  | 3.88 ms  | 5.19 ms  | 7.93 ms  | 11.00 ms | 19.10 ms | 28.27 ms | 50.02 ms | 83.30 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 |  108.5 us |  89.49 us |  92.45 us |  158.9 us |
|   3 |  117.7 us |  104.2 us |  265.6 us |   1.65 ms |
|   4 |  119.5 us |  171.5 us |   1.63 ms |  26.81 ms |
|   5 |  125.9 us |  471.6 us |  12.43 ms |  414.4 ms |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and n=3, and w=1 for n>=4.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.1 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales with ring size: 128 ms at n=255, 404 ms at n=1023,
  735 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 2.98 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.85 ms at n=255,
  ~3.8 ms at n=1023, ~7.6 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (259 us) + n * `ring_verify` (3.01 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~48 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~7.9 ms base + ~0.30 ms per additional
proof. The standalone Pedersen `batch_verify` slope over the same range is
~0.054 ms/proof, leaving ~0.25 ms/proof for the ring multi-pairing.

Sequential marginal cost per proof: ~0.048 ms (prepare) + ~0.30 ms (verify) = ~0.35 ms,
or ~8.6x cheaper than simple verification (3.01 ms). With parallel prepare, the
per-proof prepare cost drops to ~3.3 us at n=256, giving ~0.31 ms marginal, or ~9.8x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.27 ms  |    3.40 ms  |    3.40 ms  |         0.96x |         0.96x |
|   2 |    6.27 ms  |    3.97 ms  |    3.97 ms  |         1.58x |         1.58x |
|   4 |   12.28 ms  |    5.36 ms  |    5.31 ms  |         2.29x |         2.31x |
|   8 |   24.31 ms  |    8.30 ms  |    8.10 ms  |         2.93x |         3.00x |
|  16 |   48.35 ms  |   11.79 ms  |   11.24 ms  |         4.10x |         4.30x |
|  32 |   96.45 ms  |   20.74 ms  |   19.35 ms  |         4.65x |         4.98x |
|  64 |  192.63 ms  |   31.49 ms  |   28.47 ms  |         6.12x |         6.77x |
| 128 |  385.01 ms  |   56.19 ms  |   50.53 ms  |         6.85x |         7.62x |
| 256 |  769.76 ms  |   95.62 ms  |   84.13 ms  |         8.05x |         9.15x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.36 ms |  3.36 ms  |
|   2 |    3.88 ms |  1.94 ms  |
|   4 |    5.19 ms |  1.30 ms  |
|   8 |    7.93 ms |  0.99 ms  |
|  16 |   11.00 ms |  0.69 ms  |
|  32 |   19.10 ms |  0.60 ms  |
|  64 |   28.27 ms |  0.44 ms  |
| 128 |   50.02 ms |  0.39 ms  |
| 256 |   83.30 ms |  0.33 ms  |

Amortized cost per proof drops from 3.36 ms (n=1) to 0.33 ms (n=256), roughly 10x.
Two factors contribute: the fixed-cost ring multi-pairing base (~2.8 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
