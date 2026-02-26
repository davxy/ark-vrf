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
| key_from_seed                | 84.1 us  |
| key_from_scalar              | 82.0 us  |
| vrf_output                   | 80.8 us  |
| hash_to_curve_ell2_rfc_9380  | 74.5 us  |
| challenge_rfc_9381           | 920 ns   |
| point_to_hash_rfc_9381       | 336.7 ns |
| nonce_rfc_8032               | 2.26 us  |
| point_encode                 | 46.0 ns  |
| point_decode                 | 15.3 us  |
| scalar_encode                | 21.2 ns  |
| scalar_decode                | 120.9 ns |

## IETF VRF Operations (`ietf.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| ietf_prove             | 169.5 us |
| ietf_verify            | 258.1 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 482.6 us |
| pedersen_verify        | 358.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 0.91 us  | 1.84 us  | 3.65 us  | 6.73 us  | 13.4 us  | 27.3 us  | 60.2 us  | 115.6 us | 229.6 us |
| batch_verify         | 507.6 us | 600.2 us | 711.9 us | 1.63 ms  | 1.98 ms  | 3.36 ms  | 6.24 ms  | 8.41 ms  | 14.8 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.84 ms   | 3.91 ms   | 8.43 ms   |
| ring_prover_key        | 44.4 ms   | 136.6 ms  | 250.0 ms  |
| ring_verifier_key      | 44.1 ms   | 137.1 ms  | 244.0 ms  |
| ring_prove             | 150.0 ms  | 464.7 ms  | 820.3 ms  |
| ring_verify            | 3.51 ms   | 3.49 ms   | 3.24 ms   |
| ring_verifier_from_key | 255.7 us  | 275.4 us  | 317.8 us  |
| ring_vk_from_commitment| 74.4 ns   | 74.7 ns   | 69.7 ns   |
| ring_vk_builder_create | 314.5 ms  | 1.457 s   | 3.075 s   |
| ring_vk_builder_append | 16.3 ms   | 47.9 ms   | 81.1 ms   |
| ring_vk_builder_finalize | 108.9 ns | 108.8 ns  | 101.2 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 258 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 51.8 us  | 97.4 us  | 215.8 us | 433.5 us | 826.6 us | 1.66 ms  | 3.34 ms  | 6.63 ms  | 14.4 ms  |
| batch_prepare_seq  | 40.8 us  | 82.8 us  | 182.4 us | 361.5 us | 754.5 us | 1.53 ms  | 3.38 ms  | 6.10 ms  | 12.3 ms  |
| batch_prepare_par  | 41.1 us  | 69.0 us  | 107.8 us | 157.9 us | 239.7 us | 248.6 us | 233.1 us | 474.0 us | 823.0 us |
| batch_push_prepared| 5.2 us   | 10.5 us  | 19.8 us  | 39.8 us  | 69.9 us  | 171.7 us | 268.0 us | 543.2 us | 1.14 ms  |
| batch_verify       | 3.28 ms  | 4.17 ms  | 5.48 ms  | 8.03 ms  | 12.8 ms  | 20.5 ms  | 32.7 ms  | 54.7 ms  | 89.9 ms  |

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
