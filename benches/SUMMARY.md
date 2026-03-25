# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-03-25
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.19.6
- Rust: 1.93.0 (254b59607 2026-01-19)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 80.0 us  |
| data_to_point_tai            | 20.6 us  |
| data_to_point_ell2           | 67.3 us  |
| point_to_hash                | 600 ns   |
| challenge                    | 1.12 us  |
| nonce_rfc_8032               | 2.07 us  |

## IETF VRF Operations (`ietf.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| ietf_prove             | 172.0 us |
| ietf_verify            | 273.6 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 339.4 us |
| pedersen_verify        | 352.0 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.11 us  | 2.22 us  | 5.12 us  | 9.05 us  | 17.8 us  | 41.8 us  | 76.5 us  | 153.6 us | 310.4 us |
| batch_verify         | 474.8 us | 553.8 us | 860.6 us | 1.65 ms  | 2.06 ms  | 3.68 ms  | 6.23 ms  | 8.62 ms  | 15.4 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 284.0 us |
| thin_verify            | 309.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.81 us  | 3.73 us  | 7.33 us  | 14.6 us  | 33.2 us  | 58.6 us  | 121.7 us | 269.0 us | 513.8 us |
| batch_verify         | 522.1 us | 526.6 us | 798.6 us | 1.61 ms  | 1.91 ms  | 3.69 ms  | 5.56 ms  | 8.08 ms  | 14.5 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.79 ms   | 3.60 ms   | 8.31 ms   |
| ring_prover_key        | 43.8 ms   | 136.6 ms  | 244.7 ms  |
| ring_verifier_key      | 44.0 ms   | 134.2 ms  | 237.3 ms  |
| ring_prove             | 149.7 ms  | 452.2 ms  | 799.3 ms  |
| ring_verify            | 3.34 ms   | 3.38 ms   | 3.37 ms   |
| ring_verifier_from_key | 273.6 us  | 293.5 us  | 328.8 us  |
| ring_vk_from_commitment| 70.7 ns   | 71.4 ns   | 69.7 ns   |
| ring_vk_builder_create | 309.6 ms  | 1.453 s   | 2.949 s   |
| ring_vk_builder_append | 14.8 ms   | 47.8 ms   | 78.1 ms   |
| ring_vk_builder_finalize | 96.9 ns | 105.7 ns  | 117.3 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 275 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 48.3 us  | 95.5 us  | 196.1 us | 434.5 us | 889.1 us | 1.63 ms  | 3.60 ms  | 6.49 ms  | 13.1 ms  |
| batch_prepare_seq  | 40.4 us  | 81.4 us  | 166.0 us | 356.3 us | 800.7 us | 1.50 ms  | 3.28 ms  | 6.80 ms  | 12.0 ms  |
| batch_prepare_par  | 40.6 us  | 81.0 us  | 105.8 us | 145.0 us | 214.4 us | 244.6 us | 236.9 us | 467.4 us | 811.4 us |
| batch_push_prepared| 5.0 us   | 9.1 us   | 20.0 us  | 34.8 us  | 67.4 us  | 132.9 us | 269.3 us | 529.3 us | 1.04 ms  |
| batch_verify       | 3.19 ms  | 3.94 ms  | 6.05 ms  | 8.55 ms  | 11.6 ms  | 20.3 ms  | 30.6 ms  | 50.8 ms  | 88.7 ms  |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 120.9 us  | 91.5 us   | 96.7 us   | 164.8 us  |
|   3 | 119.7 us  | 122.9 us  | 285.4 us  | 1.68 ms   |
|   4 | 131.2 us  | 194.9 us  | 1.68 ms   | 33.4 ms   |
|   5 | 138.9 us  | 498.2 us  | 13.0 ms   | 577.3 ms  |

Table size is (2^w - 1)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.4 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 150 ms at n=255, 452 ms at n=1023,
  799 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 2.9 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-120 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (294 us) + n * `ring_verify` (3.38 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~48 us/proof) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit gives ~2.9 ms base + ~0.34 ms per additional proof.
The ring multi-pairing marginal cost is ~0.31 ms/proof; the Pedersen MSM adds
~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.34 ms (verify) = ~0.39 ms,
or ~8.7x cheaper than simple verification (3.38 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.34 ms marginal, or ~9.9x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.67 ms  |    3.23 ms  |    3.23 ms  |         1.14x |         1.14x |
|   2 |    7.05 ms  |    4.02 ms  |    4.01 ms  |         1.75x |         1.76x |
|   4 |   13.81 ms  |    6.22 ms  |    6.15 ms  |         2.22x |         2.25x |
|   8 |   27.33 ms  |    8.91 ms  |    8.70 ms  |         3.07x |         3.14x |
|  16 |   54.37 ms  |   12.42 ms  |   11.83 ms  |         4.38x |         4.59x |
|  32 |  108.45 ms  |   21.80 ms  |   20.54 ms  |         4.97x |         5.28x |
|  64 |  216.61 ms  |   33.86 ms  |   30.82 ms  |         6.40x |         7.03x |
| 128 |  432.93 ms  |   57.60 ms  |   51.27 ms  |         7.52x |         8.44x |
| 256 |  865.57 ms  |  100.75 ms  |   89.51 ms  |         8.59x |         9.67x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.19 ms |  3.19 ms  |
|   2 |    3.94 ms |  1.97 ms  |
|   4 |    6.05 ms |  1.51 ms  |
|   8 |    8.55 ms |  1.07 ms  |
|  16 |   11.6 ms  |  0.73 ms  |
|  32 |   20.3 ms  |  0.63 ms  |
|  64 |   30.6 ms  |  0.48 ms  |
| 128 |   50.8 ms  |  0.40 ms  |
| 256 |   88.7 ms  |  0.35 ms  |

Amortized cost per proof drops from 3.19 ms (n=1) to 0.35 ms (n=256), roughly 9x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.2 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
