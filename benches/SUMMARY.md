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
| pedersen_prove         | 371.5 us |
| pedersen_verify        | 362.0 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.24 us  | 2.46 us  | 4.95 us  | 9.79 us  | 19.8 us  | 38.9 us  | 83.1 us  | 156.0 us | 314.6 us |
| batch_verify         | 517.3 us | 601.6 us | 783.9 us | 1.75 ms  | 2.16 ms  | 3.45 ms  | 6.26 ms  | 8.54 ms  | 15.5 ms  |

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
| ring_params_setup      | 0.86 ms   | 3.92 ms   | 8.42 ms   |
| ring_prover_key        | 44.6 ms   | 137.5 ms  | 249.6 ms  |
| ring_verifier_key      | 44.9 ms   | 136.7 ms  | 250.1 ms  |
| ring_prove             | 150.1 ms  | 451.5 ms  | 873.7 ms  |
| ring_verify            | 3.45 ms   | 3.17 ms   | 3.54 ms   |
| ring_verifier_from_key | 261.3 us  | 262.8 us  | 316.9 us  |
| ring_vk_from_commitment| 74.7 ns   | 69.1 ns   | 69.5 ns   |
| ring_vk_builder_create | 317.8 ms  | 1.403 s   | 3.200 s   |
| ring_vk_builder_append | 16.4 ms   | 48.3 ms   | 81.4 ms   |
| ring_vk_builder_finalize | 108.7 ns | 109.2 ns  | 106.2 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 267 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 50.1 us  | 103.4 us | 214.4 us | 435.9 us | 826.4 us | 1.65 ms  | 3.53 ms  | 6.66 ms  | 14.4 ms  |
| batch_prepare_seq  | 41.5 us  | 87.7 us  | 180.4 us | 366.3 us | 840.7 us | 1.51 ms  | 3.02 ms  | 6.14 ms  | 13.0 ms  |
| batch_prepare_par  | 41.0 us  | 75.7 us  | 99.0 us  | 148.2 us | 219.5 us | 244.7 us | 232.0 us | 483.1 us | 765.1 us |
| batch_push_prepared| 5.7 us   | 9.7 us   | 19.7 us  | 35.5 us  | 75.5 us  | 134.0 us | 266.3 us | 527.9 us | 1.12 ms  |
| batch_verify       | 3.53 ms  | 4.49 ms  | 5.91 ms  | 8.19 ms  | 12.6 ms  | 20.7 ms  | 31.5 ms  | 60.1 ms  | 91.9 ms  |

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
