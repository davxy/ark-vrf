# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-04-02
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.19.10
- Rust: 1.93.0 (254b59607 2026-01-19)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 77.2 us  |
| data_to_point_tai            | 20.9 us  |
| data_to_point_ell2           | 68.5 us  |
| point_to_hash                | 623 ns   |
| challenge                    | 1.10 us  |
| nonce_rfc_8032               | 2.04 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 184.2 us |
| tiny_verify            | 187.6 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 382.8 us |
| pedersen_verify        | 219.8 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.23 us  | 2.43 us  | 4.78 us  | 9.49 us  | 19.1 us  | 36.0 us  | 72.0 us  | 143.4 us | 304.2 us |
| batch_verify         | 503.4 us | 595.0 us | 719.9 us | 1.75 ms  | 2.12 ms  | 3.77 ms  | 5.74 ms  | 7.94 ms  | 15.2 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 193.2 us |
| thin_verify            | 197.9 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.88 us  | 3.77 us  | 7.54 us  | 15.0 us  | 28.1 us  | 61.2 us  | 123.3 us | 246.6 us | 495.8 us |
| batch_verify         | 474.9 us | 546.0 us | 703.1 us | 1.67 ms  | 2.01 ms  | 3.40 ms  | 5.88 ms  | 7.88 ms  | 14.0 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.80 ms   | 3.70 ms   | 9.08 ms   |
| ring_prover_key        | 42.2 ms   | 129.5 ms  | 235.0 ms  |
| ring_verifier_key      | 44.7 ms   | 137.7 ms  | 251.3 ms  |
| ring_prove             | 150.6 ms  | 481.6 ms  | 884.9 ms  |
| ring_verify            | 3.30 ms   | 3.28 ms   | 3.23 ms   |
| ring_verifier_from_key | 257.2 us  | 277.0 us  | 315.2 us  |
| ring_vk_from_commitment| 74.7 ns   | 74.6 ns   | 75.3 ns   |
| ring_vk_builder_create | 307.7 ms  | 1.459 s   | 3.139 s   |
| ring_vk_builder_append | 15.3 ms   | 45.1 ms   | 81.9 ms   |
| ring_vk_builder_finalize | 111.5 ns | 101.3 ns  | 112.3 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 269 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 49.9 us  | 102.9 us | 222.3 us | 408.5 us | 887.1 us | 1.78 ms  | 3.52 ms  | 6.63 ms  | 14.4 ms  |
| batch_prepare_seq  | 47.4 us  | 88.7 us  | 178.5 us | 395.7 us | 801.7 us | 1.62 ms  | 3.26 ms  | 6.12 ms  | 12.3 ms  |
| batch_prepare_par  | 44.1 us  | 74.7 us  | 108.6 us | 156.1 us | 219.4 us | 248.7 us | 262.4 us | 497.7 us | 798.3 us |
| batch_push_prepared| 5.7 us   | 9.8 us   | 22.1 us  | 39.5 us  | 72.9 us  | 147.6 us | 263.5 us | 523.6 us | 1.07 ms  |
| batch_verify       | 3.49 ms  | 4.31 ms  | 5.86 ms  | 8.61 ms  | 12.7 ms  | 20.9 ms  | 31.1 ms  | 52.3 ms  | 92.9 ms  |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 115.8 us  | 87.9 us   | 94.6 us   | 160.3 us  |
|   3 | 117.6 us  | 105.4 us  | 264.6 us  | 1.64 ms   |
|   4 | 121.1 us  | 178.6 us  | 1.62 ms   | 24.7 ms   |
|   5 | 120.3 us  | 447.9 us  | 11.8 ms   | 537.0 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.3 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 151 ms at n=255, 482 ms at n=1023,
  885 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.1 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-112 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (277 us) + n * `ring_verify` (3.28 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~47 us/proof) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit gives ~3.1 ms base + ~0.35 ms per additional proof.
The ring multi-pairing marginal cost is ~0.32 ms/proof; the Pedersen MSM adds
~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.35 ms (verify) = ~0.40 ms,
or ~8.2x cheaper than simple verification (3.28 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.35 ms marginal, or ~9.4x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.56 ms  |    3.54 ms  |    3.53 ms  |         1.01x |         1.01x |
|   2 |    6.84 ms  |    4.40 ms  |    4.39 ms  |         1.55x |         1.56x |
|   4 |   13.39 ms  |    6.04 ms  |    5.97 ms  |         2.22x |         2.24x |
|   8 |   26.50 ms  |    9.01 ms  |    8.77 ms  |         2.94x |         3.02x |
|  16 |   52.73 ms  |   13.50 ms  |   12.92 ms  |         3.91x |         4.08x |
|  32 |  105.18 ms  |   22.52 ms  |   21.15 ms  |         4.67x |         4.97x |
|  64 |  210.07 ms  |   34.37 ms  |   31.37 ms  |         6.11x |         6.70x |
| 128 |  419.87 ms  |   58.42 ms  |   52.80 ms  |         7.19x |         7.95x |
| 256 |  839.45 ms  |  105.20 ms  |   93.73 ms  |         7.98x |         8.96x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.49 ms |  3.49 ms  |
|   2 |    4.31 ms |  2.16 ms  |
|   4 |    5.86 ms |  1.47 ms  |
|   8 |    8.61 ms |  1.08 ms  |
|  16 |   12.7 ms  |  0.79 ms  |
|  32 |   20.9 ms  |  0.65 ms  |
|  64 |   31.1 ms  |  0.49 ms  |
| 128 |   52.3 ms  |  0.41 ms  |
| 256 |   92.9 ms  |  0.36 ms  |

Amortized cost per proof drops from 3.49 ms (n=1) to 0.36 ms (n=256), roughly 9.7x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.5 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
