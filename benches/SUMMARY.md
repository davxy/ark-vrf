# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-03-27
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
| vrf_output                   | 77.6 us  |
| data_to_point_tai            | 20.5 us  |
| data_to_point_ell2           | 70.6 us  |
| point_to_hash                | 608 ns   |
| challenge                    | 1.10 us  |
| nonce_rfc_8032               | 2.03 us  |

## IETF VRF Operations (`ietf.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| ietf_prove             | 271.9 us |
| ietf_verify            | 300.4 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 382.2 us |
| pedersen_verify        | 219.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.22 us  | 2.43 us  | 4.85 us  | 9.11 us  | 19.5 us  | 38.6 us  | 72.0 us  | 153.2 us | 287.2 us |
| batch_verify         | 508.1 us | 591.1 us | 767.8 us | 1.78 ms  | 2.12 ms  | 3.34 ms  | 5.76 ms  | 7.85 ms  | 14.2 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 193.1 us |
| thin_verify            | 197.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.88 us  | 3.76 us  | 7.46 us  | 15.1 us  | 30.0 us  | 60.8 us  | 123.0 us | 241.8 us | 491.8 us |
| batch_verify         | 473.7 us | 550.5 us | 695.7 us | 1.72 ms  | 2.01 ms  | 3.39 ms  | 5.94 ms  | 7.88 ms  | 14.1 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.85 ms   | 3.91 ms   | 7.83 ms   |
| ring_prover_key        | 44.6 ms   | 137.6 ms  | 235.4 ms  |
| ring_verifier_key      | 44.4 ms   | 137.9 ms  | 248.1 ms  |
| ring_prove             | 150.3 ms  | 480.0 ms  | 879.7 ms  |
| ring_verify            | 3.29 ms   | 3.27 ms   | 3.05 ms   |
| ring_verifier_from_key | 257.3 us  | 278.9 us  | 288.2 us  |
| ring_vk_from_commitment| 71.7 ns   | 71.9 ns   | 71.6 ns   |
| ring_vk_builder_create | 317.7 ms  | 1.371 s   | 3.130 s   |
| ring_vk_builder_append | 16.3 ms   | 50.5 ms   | 87.0 ms   |
| ring_vk_builder_finalize | 106.4 ns | 98.0 ns   | 105.4 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 263 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 48.7 us  | 97.5 us  | 201.3 us | 461.0 us | 875.2 us | 1.67 ms  | 3.47 ms  | 6.61 ms  | 14.0 ms  |
| batch_prepare_seq  | 44.9 us  | 82.5 us  | 169.4 us | 394.0 us | 798.6 us | 1.67 ms  | 3.50 ms  | 6.10 ms  | 13.0 ms  |
| batch_prepare_par  | 41.8 us  | 80.7 us  | 113.9 us | 161.4 us | 223.4 us | 286.2 us | 394.3 us | 444.1 us | 790.6 us |
| batch_push_prepared| 5.2 us   | 10.4 us  | 19.0 us  | 37.7 us  | 69.7 us  | 136.2 us | 270.2 us | 529.1 us | 1.18 ms  |
| batch_verify       | 3.27 ms  | 4.07 ms  | 5.97 ms  | 8.49 ms  | 11.9 ms  | 21.5 ms  | 34.8 ms  | 55.2 ms  | 94.8 ms  |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 115.0 us  | 87.1 us   | 93.0 us   | 159.6 us  |
|   3 | 117.5 us  | 104.6 us  | 261.7 us  | 1.60 ms   |
|   4 | 119.3 us  | 176.0 us  | 1.61 ms   | 24.8 ms   |
|   5 | 126.0 us  | 469.3 us  | 12.3 ms   | 494.6 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 150 ms at n=255, 480 ms at n=1023,
  880 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.1 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-112 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (279 us) + n * `ring_verify` (3.27 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~45 us/proof) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit gives ~2.9 ms base + ~0.36 ms per additional proof.
The ring multi-pairing marginal cost is ~0.33 ms/proof; the Pedersen MSM adds
~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.36 ms (verify) = ~0.41 ms,
or ~8.0x cheaper than simple verification (3.27 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.36 ms marginal, or ~9.1x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.55 ms  |    3.32 ms  |    3.31 ms  |         1.07x |         1.07x |
|   2 |    6.82 ms  |    4.15 ms  |    4.15 ms  |         1.64x |         1.64x |
|   4 |   13.36 ms  |    6.14 ms  |    6.08 ms  |         2.18x |         2.20x |
|   8 |   26.44 ms  |    8.88 ms  |    8.65 ms  |         2.98x |         3.06x |
|  16 |   52.60 ms  |   12.73 ms  |   12.15 ms  |         4.13x |         4.33x |
|  32 |  104.92 ms  |   23.17 ms  |   21.79 ms  |         4.53x |         4.82x |
|  64 |  209.56 ms  |   38.30 ms  |   35.24 ms  |         5.47x |         5.95x |
| 128 |  418.84 ms  |   61.30 ms  |   55.64 ms  |         6.83x |         7.53x |
| 256 |  837.40 ms  |  107.80 ms  |   95.59 ms  |         7.77x |         8.76x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.27 ms |  3.27 ms  |
|   2 |    4.07 ms |  2.04 ms  |
|   4 |    5.97 ms |  1.49 ms  |
|   8 |    8.49 ms |  1.06 ms  |
|  16 |   11.9 ms  |  0.74 ms  |
|  32 |   21.5 ms  |  0.67 ms  |
|  64 |   34.8 ms  |  0.54 ms  |
| 128 |   55.2 ms  |  0.43 ms  |
| 256 |   94.8 ms  |  0.37 ms  |

Amortized cost per proof drops from 3.27 ms (n=1) to 0.37 ms (n=256), roughly 8.8x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.2 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
