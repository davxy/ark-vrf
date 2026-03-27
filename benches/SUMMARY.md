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
| vrf_output                   | 79.8 us  |
| data_to_point_tai            | 19.9 us  |
| data_to_point_ell2           | 67.0 us  |
| point_to_hash                | 588 ns   |
| challenge                    | 1.10 us  |
| nonce_rfc_8032               | 2.04 us  |

## IETF VRF Operations (`ietf.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| ietf_prove             | 172.1 us |
| ietf_verify            | 211.5 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 364.1 us |
| pedersen_verify        | 238.2 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.21 us  | 2.49 us  | 4.84 us  | 9.03 us  | 18.0 us  | 40.0 us  | 77.7 us  | 155.2 us | 310.7 us |
| batch_verify         | 473.1 us | 597.8 us | 775.8 us | 1.63 ms  | 2.00 ms  | 3.64 ms  | 6.25 ms  | 8.78 ms  | 15.5 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 290.1 us |
| thin_verify            | 277.6 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.95 us  | 3.94 us  | 7.83 us  | 15.6 us  | 31.0 us  | 63.5 us  | 128.2 us | 256.5 us | 512.9 us |
| batch_verify         | 477.3 us | 517.0 us | 657.0 us | 1.71 ms  | 2.03 ms  | 3.42 ms  | 5.89 ms  | 7.84 ms  | 14.2 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.78 ms   | 3.70 ms   | 8.35 ms   |
| ring_prover_key        | 42.1 ms   | 125.2 ms  | 243.4 ms  |
| ring_verifier_key      | 43.0 ms   | 124.8 ms  | 224.6 ms  |
| ring_prove             | 145.3 ms  | 456.1 ms  | 794.2 ms  |
| ring_verify            | 3.31 ms   | 3.32 ms   | 3.28 ms   |
| ring_verifier_from_key | 259.5 us  | 276.2 us  | 310.1 us  |
| ring_vk_from_commitment| 75.2 ns   | 74.7 ns   | 74.5 ns   |
| ring_vk_builder_create | 307.5 ms  | 1.367 s   | 3.016 s   |
| ring_vk_builder_append | 16.0 ms   | 47.0 ms   | 76.7 ms   |
| ring_vk_builder_finalize | 106.2 ns | 105.6 ns  | 111.8 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 261 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 48.2 us  | 95.7 us  | 214.1 us | 428.8 us | 851.3 us | 1.67 ms  | 3.27 ms  | 7.06 ms  | 15.0 ms  |
| batch_prepare_seq  | 44.9 us  | 89.3 us  | 179.7 us | 389.1 us | 783.3 us | 1.53 ms  | 3.00 ms  | 6.03 ms  | 12.1 ms  |
| batch_prepare_par  | 43.4 us  | 74.2 us  | 105.6 us | 138.7 us | 216.4 us | 232.4 us | 216.0 us | 423.6 us | 771.7 us |
| batch_push_prepared| 5.4 us   | 9.9 us   | 18.9 us  | 37.5 us  | 74.7 us  | 132.4 us | 265.1 us | 520.6 us | 1.06 ms  |
| batch_verify       | 3.41 ms  | 4.25 ms  | 5.71 ms  | 8.48 ms  | 12.5 ms  | 19.3 ms  | 30.6 ms  | 56.3 ms  | 96.9 ms  |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 114.8 us  | 87.1 us   | 101.0 us  | 158.1 us  |
|   3 | 117.0 us  | 105.7 us  | 268.0 us  | 1.61 ms   |
|   4 | 119.6 us  | 163.6 us  | 1.50 ms   | 23.0 ms   |
|   5 | 122.9 us  | 437.5 us  | 12.6 ms   | 488.9 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.3 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 145 ms at n=255, 456 ms at n=1023,
  794 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.0 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-112 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (276 us) + n * `ring_verify` (3.32 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~45 us/proof) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit gives ~2.9 ms base + ~0.37 ms per additional proof.
The ring multi-pairing marginal cost is ~0.34 ms/proof; the Pedersen MSM adds
~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.37 ms (verify) = ~0.42 ms,
or ~7.9x cheaper than simple verification (3.32 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.37 ms marginal, or ~9.0x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.60 ms  |    3.46 ms  |    3.45 ms  |         1.04x |         1.04x |
|   2 |    6.92 ms  |    4.34 ms  |    4.32 ms  |         1.59x |         1.60x |
|   4 |   13.56 ms  |    5.89 ms  |    5.82 ms  |         2.30x |         2.33x |
|   8 |   26.84 ms  |    8.87 ms  |    8.62 ms  |         3.03x |         3.11x |
|  16 |   53.40 ms  |   13.28 ms  |   12.72 ms  |         4.02x |         4.20x |
|  32 |  106.52 ms  |   20.83 ms  |   19.53 ms  |         5.11x |         5.45x |
|  64 |  212.76 ms  |   33.60 ms  |   30.82 ms  |         6.33x |         6.90x |
| 128 |  425.24 ms  |   62.33 ms  |   56.72 ms  |         6.82x |         7.50x |
| 256 |  850.20 ms  |  109.00 ms  |   97.67 ms  |         7.80x |         8.70x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.41 ms |  3.41 ms  |
|   2 |    4.25 ms |  2.13 ms  |
|   4 |    5.71 ms |  1.43 ms  |
|   8 |    8.48 ms |  1.06 ms  |
|  16 |   12.5 ms  |  0.78 ms  |
|  32 |   19.3 ms  |  0.60 ms  |
|  64 |   30.6 ms  |  0.48 ms  |
| 128 |   56.3 ms  |  0.44 ms  |
| 256 |   96.9 ms  |  0.38 ms  |

Amortized cost per proof drops from 3.41 ms (n=1) to 0.38 ms (n=256), roughly 9x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.2 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
