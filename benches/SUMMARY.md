# Benchmark Baseline

Suite: `Bandersnatch-XOF:SHA512-ELL2:XMD:SHA512-v1` (Twisted Edwards on BLS12-381)
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
| vrf_output                   | 78.5 us  |
| data_to_point_tai            | 22.5 us  |
| data_to_point_ell2           | 67.0 us  |
| point_to_hash                | 607 ns   |
| challenge                    | 1.11 us  |
| nonce                        | 2.07 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 179.9 us |
| tiny_verify            | 189.7 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 361.3 us |
| pedersen_verify        | 227.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.20 us  | 2.40 us  | 4.86 us  | 9.85 us  | 19.4 us  | 38.2 us  | 76.2 us  | 144.6 us | 285.7 us |
| batch_verify         | 506.6 us | 599.6 us | 763.3 us | 1.74 ms  | 2.11 ms  | 3.62 ms  | 5.81 ms  | 8.81 ms  | 14.3 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 187.1 us |
| thin_verify            | 189.7 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.96 us  | 3.92 us  | 7.73 us  | 15.6 us  | 31.2 us  | 63.5 us  | 127.4 us | 255.0 us | 512.0 us |
| batch_verify         | 488.3 us | 554.7 us | 723.5 us | 1.69 ms  | 2.03 ms  | 3.46 ms  | 5.88 ms  | 7.88 ms  | 14.3 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.84 ms   | 3.84 ms   | 8.63 ms   |
| ring_context_setup     | 0.80 ms   | 3.59 ms   | 8.26 ms   |
| ring_prover_key        | 41.9 ms   | 129.1 ms  | 248.5 ms  |
| ring_verifier_key      | 43.3 ms   | 141.3 ms  | 252.4 ms  |
| ring_prove             | 151.0 ms  | 460.7 ms  | 879.1 ms  |
| ring_verify            | 3.33 ms   | 3.37 ms   | 3.35 ms   |
| ring_verifier_from_key | 265.2 us  | 285.4 us  | 303.1 us  |
| ring_vk_from_commitment| 71.2 ns   | 71.4 ns   | 76.5 ns   |
| ring_vk_builder_create | 317.2 ms  | 1.412 s   | 3.174 s   |
| ring_vk_builder_append | 16.4 ms   | 48.4 ms   | 81.8 ms   |
| ring_vk_builder_finalize | 105.8 ns | 105.8 ns | 98.7 ns   |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 280 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 50.5 us  | 97.8 us  | 198.9 us | 464.8 us | 869.4 us | 1.76 ms  | 3.40 ms  | 6.65 ms  | 13.5 ms  |
| batch_prepare_seq  | 45.1 us  | 83.3 us  | 169.0 us | 376.1 us | 810.3 us | 1.63 ms  | 3.38 ms  | 6.26 ms  | 12.4 ms  |
| batch_prepare_par  | 47.2 us  | 75.5 us  | 111.2 us | 161.1 us | 217.2 us | 227.2 us | 209.7 us | 433.0 us | 799.7 us |
| batch_push_prepared| 5.2 us   | 9.3 us   | 20.3 us  | 36.9 us  | 69.4 us  | 131.1 us | 279.2 us | 525.3 us | 1.12 ms  |
| batch_verify       | 3.44 ms  | 4.58 ms  | 5.54 ms  | 8.84 ms  | 12.8 ms  | 23.7 ms  | 33.2 ms  | 52.3 ms  | 95.5 ms  |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 122.4 us  | 90.6 us   | 96.1 us   | 162.2 us  |
|   3 | 121.9 us  | 107.5 us  | 268.8 us  | 1.66 ms   |
|   4 | 124.6 us  | 181.0 us  | 1.65 ms   | 25.4 ms   |
|   5 | 130.7 us  | 474.6 us  | 12.5 ms   | 504.7 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.35 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 151 ms at n=255, 461 ms at n=1023,
  879 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.2 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-110 ns).
- `ring_context_setup` and `ring_params_setup` have similar cost (~0.8 ms at n=255,
  ~3.7 ms at n=1023, ~8.4 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (285 us) + n * `ring_verify` (3.37 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~48 us/proof seq) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit (n=8..256) gives ~5 ms base + ~0.35 ms per additional
proof. The ring multi-pairing marginal cost is ~0.32 ms/proof; the Pedersen MSM
adds ~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.048 ms (prepare) + ~0.35 ms (verify) = ~0.40 ms,
or ~8.4x cheaper than simple verification (3.37 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.35 ms marginal, or ~9.6x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.66 ms  |    3.49 ms  |    3.49 ms  |         1.05x |         1.05x |
|   2 |    7.03 ms  |    4.66 ms  |    4.66 ms  |         1.51x |         1.51x |
|   4 |   13.77 ms  |    5.71 ms  |    5.65 ms  |         2.41x |         2.44x |
|   8 |   27.25 ms  |    9.22 ms  |    9.00 ms  |         2.96x |         3.03x |
|  16 |   54.21 ms  |   13.66 ms  |   13.07 ms  |         3.97x |         4.15x |
|  32 |  108.13 ms  |   25.35 ms  |   23.95 ms  |         4.27x |         4.51x |
|  64 |  215.97 ms  |   36.54 ms  |   33.37 ms  |         5.91x |         6.47x |
| 128 |  431.65 ms  |   58.54 ms  |   52.71 ms  |         7.37x |         8.19x |
| 256 |  863.01 ms  |  107.86 ms  |   96.29 ms  |         8.00x |         8.96x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.44 ms |  3.44 ms  |
|   2 |    4.58 ms |  2.29 ms  |
|   4 |    5.54 ms |  1.38 ms  |
|   8 |    8.84 ms |  1.10 ms  |
|  16 |   12.8 ms  |  0.80 ms  |
|  32 |   23.7 ms  |  0.74 ms  |
|  64 |   33.2 ms  |  0.52 ms  |
| 128 |   52.3 ms  |  0.41 ms  |
| 256 |   95.5 ms  |  0.37 ms  |

Amortized cost per proof drops from 3.44 ms (n=1) to 0.37 ms (n=256), roughly 9.3x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.5 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
