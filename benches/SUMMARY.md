# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-02-18
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.18.9
- Rust: 1.93.0 (254b59607 2026-01-19)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 81.7 us  |
| data_to_point_tai            | 48.3 us  |
| data_to_point_ell2           | 70.3 us  |
| point_to_hash                | 354 ns   |
| challenge                    | 866 ns   |
| nonce_rfc_8032               | 1.79 us  |

### Delinearization

| Benchmark      | n=2     | n=4     | n=8     | n=16    | n=32    | n=64    | n=128   | n=256   |
|:---------------|---------|---------|---------|---------|---------|---------|---------|---------|
| delinearize    | 174 us  | 360 us  | 720 us  | 1.11 ms | 2.07 ms | 3.41 ms | 4.15 ms | 7.19 ms |

Uses a hybrid strategy: sequential fold for N < 16, MSM (Pippenger) for N >= 16.
Small N avoids MSM's bucket-setup overhead; large N benefits from sublinear scaling.

## IETF VRF Operations (`ietf.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| ietf_prove             | 165.4 us |
| ietf_verify            | 266.4 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 478.0 us |
| pedersen_verify        | 377.9 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 0.99 us  | 1.94 us  | 3.91 us  | 7.80 us  | 15.5 us  | 30.9 us  | 61.8 us  | 123.7 us | 248.0 us |
| batch_verify         | 507.3 us | 593.8 us | 773.3 us | 1.79 ms  | 2.13 ms  | 3.63 ms  | 6.21 ms  | 8.51 ms  | 15.4 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 310.6 us |
| thin_verify            | 355.9 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 2.00 us  | 3.68 us  | 7.44 us  | 15.8 us  | 29.5 us  | 64.5 us  | 132.4 us | 261.2 us | 521.1 us |
| batch_verify         | 490.2 us | 548.6 us | 692.5 us | 1.67 ms  | 2.18 ms  | 3.64 ms  | 6.24 ms  | 8.51 ms  | 15.1 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.85 ms   | 3.94 ms   | 7.86 ms   |
| ring_prover_key        | 44.3 ms   | 136.9 ms  | 251.8 ms  |
| ring_verifier_key      | 44.1 ms   | 136.5 ms  | 228.9 ms  |
| ring_prove             | 149.5 ms  | 462.1 ms  | 803.1 ms  |
| ring_verify            | 3.42 ms   | 3.45 ms   | 3.51 ms   |
| ring_verifier_from_key | 254.3 us  | 274.0 us  | 304.5 us  |
| ring_vk_from_commitment| 75.3 ns   | 75.0 ns   | 75.0 ns   |
| ring_vk_builder_create | 317.0 ms  | 1.381 s   | 3.066 s   |
| ring_vk_builder_append | 16.4 ms   | 44.1 ms   | 80.0 ms   |
| ring_vk_builder_finalize | 107.2 ns | 100.2 ns  | 98.6 ns   |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 269 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 48.0 us  | 102.0 us | 201.1 us | 433.2 us | 876.9 us | 1.75 ms  | 3.25 ms  | 6.50 ms  | 13.2 ms  |
| batch_prepare_seq  | 41.5 us  | 83.6 us  | 164.8 us | 384.2 us | 828.3 us | 1.61 ms  | 3.02 ms  | 6.02 ms  | 12.5 ms  |
| batch_prepare_par  | 40.2 us  | 76.4 us  | 97.2 us  | 151.8 us | 210.6 us | 237.9 us | 246.1 us | 459.7 us | 790.7 us |
| batch_push_prepared| 5.6 us   | 9.2 us   | 17.6 us  | 37.5 us  | 72.5 us  | 134.4 us | 264.9 us | 543.1 us | 1.05 ms  |
| batch_verify       | 3.45 ms  | 4.43 ms  | 5.92 ms  | 8.58 ms  | 12.7 ms  | 19.4 ms  | 30.7 ms  | 57.7 ms  | 90.7 ms  |

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.4 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 150 ms at n=255, 465 ms at n=1023,
  820 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.1 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-110 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (275 us) + n * `ring_verify` (3.49 ms).

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
or ~8.9x cheaper than simple verification (3.48 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.34 ms marginal, or ~10x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.75 ms  |    3.32 ms  |    3.31 ms  |         1.13x |         1.13x |
|   2 |    7.23 ms  |    4.25 ms  |    4.24 ms  |         1.70x |         1.71x |
|   4 |   14.19 ms  |    5.67 ms  |    5.59 ms  |         2.50x |         2.54x |
|   8 |   28.11 ms  |    8.39 ms  |    8.19 ms  |         3.35x |         3.43x |
|  16 |   55.95 ms  |   13.55 ms  |   13.04 ms  |         4.13x |         4.29x |
|  32 |  111.63 ms  |   22.16 ms  |   20.75 ms  |         5.04x |         5.38x |
|  64 |  223.00 ms  |   36.08 ms  |   32.93 ms  |         6.18x |         6.77x |
| 128 |  445.70 ms  |   60.80 ms  |   55.17 ms  |         7.33x |         8.08x |
| 256 |  891.15 ms  |  102.20 ms  |   90.72 ms  |         8.72x |         9.82x |

### Effect of Batched Pedersen Verification

The Pedersen batch MSM replaces N individual 5-point verifications (~452 us each)
with a single (5N+2)-point MSM during `verify`. This shifts cost from `prepare`
to `verify`:

| Metric (n=256)   | Before      | After       | Change       |
|:------------------|------------:|------------:|:-------------|
| prepare_seq       | 124.2 ms    | 12.3 ms     | 10.1x faster |
| prepare_par       | 4.30 ms     | 0.82 ms     | 5.2x faster  |
| batch_verify      | 80.9 ms     | 89.9 ms     | 11% slower   |
| Total (seq)       | 206.4 ms    | 102.2 ms    | 2.02x faster |
| Total (par)       | 86.5 ms     | 90.7 ms     | ~same        |

The sequential pipeline benefits most: prepare drops from ~490 us/proof to ~48 us/proof,
while the additional MSM cost in verify (~10 ms at n=256) is much smaller than the
savings. The parallel pipeline sees less net gain since prepare was already cheap
when parallelized, and the verify increase slightly offsets the savings.

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.82 ms |  3.82 ms  |
|   2 |    4.29 ms |  2.15 ms  |
|   4 |    5.83 ms |  1.46 ms  |
|   8 |    8.82 ms |  1.10 ms  |
|  16 |   11.8 ms  |  0.74 ms  |
|  32 |   20.5 ms  |  0.64 ms  |
|  64 |   30.6 ms  |  0.48 ms  |
| 128 |   52.7 ms  |  0.41 ms  |
| 256 |   91.5 ms  |  0.36 ms  |

Amortized cost per proof drops from 3.82 ms (n=1) to 0.36 ms (n=256), roughly 11x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.2 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
