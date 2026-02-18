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
| ietf_prove             | 168.7 us |
| ietf_verify            | 344.4 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 476.7 us |
| pedersen_verify        | 460.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.09 us  | 2.10 us  | 4.19 us  | 8.31 us  | 15.7 us  | 35.6 us  | 65.6 us  | 124.5 us | 250.6 us |
| batch_verify         | 508.7 us | 603.8 us | 772.6 us | 1.87 ms  | 2.01 ms  | 3.61 ms  | 6.05 ms  | 8.00 ms  | 14.5 ms  |

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
| batch_verifier_new | 263 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 48.1 us  | 107.9 us | 215.2 us | 434.8 us | 877.1 us | 1.83 ms  | 3.49 ms  | 6.61 ms  | 13.3 ms  |
| batch_prepare_seq  | 41.2 us  | 88.4 us  | 181.1 us | 389.0 us | 799.7 us | 1.61 ms  | 3.10 ms  | 7.39 ms  | 12.4 ms  |
| batch_prepare_par  | 46.1 us  | 75.3 us  | 101.7 us | 162.0 us | 209.2 us | 228.8 us | 248.3 us | 406.8 us | 777.0 us |
| batch_push_prepared| 5.1 us   | 9.6 us   | 19.4 us  | 35.4 us  | 73.4 us  | 140.7 us | 265.2 us | 547.3 us | 1.11 ms  |
| batch_verify       | 3.82 ms  | 4.29 ms  | 5.83 ms  | 8.82 ms  | 11.8 ms  | 20.5 ms  | 30.6 ms  | 52.7 ms  | 91.5 ms  |

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
batch MSM. A linear fit gives ~3.2 ms base + ~0.34 ms per additional proof.
The ring multi-pairing marginal cost is ~0.31 ms/proof; the Pedersen MSM adds
~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.34 ms (verify) = ~0.39 ms,
or ~8.9x cheaper than simple verification (3.49 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.34 ms marginal, or ~10x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.77 ms  |    3.86 ms  |    3.87 ms  |         0.98x |         0.98x |
|   2 |    7.26 ms  |    4.38 ms  |    4.36 ms  |         1.66x |         1.66x |
|   4 |   14.24 ms  |    6.01 ms  |    5.93 ms  |         2.37x |         2.40x |
|   8 |   28.20 ms  |    9.21 ms  |    8.98 ms  |         3.06x |         3.14x |
|  16 |   56.12 ms  |   12.60 ms  |   12.01 ms  |         4.45x |         4.67x |
|  32 |  111.96 ms  |   22.11 ms  |   20.73 ms  |         5.07x |         5.40x |
|  64 |  223.64 ms  |   33.70 ms  |   30.85 ms  |         6.63x |         7.25x |
| 128 |  447.00 ms  |   60.09 ms  |   53.11 ms  |         7.44x |         8.42x |
| 256 |  893.72 ms  |  103.90 ms  |   92.28 ms  |         8.60x |         9.69x |

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
