# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-04-09
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.19.11
- Rust: 1.94.1 (e408947bf 2026-03-25)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 83.1 us  |
| data_to_point_tai            | 20.7 us  |
| data_to_point_ell2           | 67.3 us  |
| point_to_hash                | 600 ns   |
| challenge                    | 1.10 us  |
| nonce_rfc_8032               | 2.02 us  |

## Tiny VRF Operations (`tiny.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| tiny_prove             | 191.3 us |
| tiny_verify            | 197.5 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 385.2 us |
| pedersen_verify        | 233.2 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.21 us  | 2.40 us  | 4.83 us  | 9.55 us  | 19.2 us  | 38.0 us  | 76.1 us  | 155.9 us | 303.6 us |
| batch_verify         | 515.9 us | 604.6 us | 777.5 us | 1.77 ms  | 2.15 ms  | 3.65 ms  | 6.18 ms  | 8.46 ms  | 15.4 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 188.4 us |
| thin_verify            | 190.9 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.90 us  | 3.83 us  | 7.59 us  | 15.3 us  | 30.6 us  | 61.6 us  | 123.5 us | 248.6 us | 513.3 us |
| batch_verify         | 489.0 us | 567.0 us | 717.6 us | 1.74 ms  | 2.04 ms  | 3.47 ms  | 5.95 ms  | 7.88 ms  | 14.4 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.85 ms   | 3.67 ms   | 8.38 ms   |
| ring_context_setup     | 0.85 ms   | 3.64 ms   | 8.35 ms   |
| ring_prover_key        | 44.9 ms   | 129.6 ms  | 250.8 ms  |
| ring_verifier_key      | 44.4 ms   | 138.1 ms  | 251.5 ms  |
| ring_prove             | 149.9 ms  | 480.9 ms  | 810.1 ms  |
| ring_verify            | 3.30 ms   | 3.27 ms   | 3.03 ms   |
| ring_verifier_from_key | 252.9 us  | 273.3 us  | 284.0 us  |
| ring_vk_from_commitment| 73.9 ns   | 76.3 ns   | 71.8 ns   |
| ring_vk_builder_create | 319.2 ms  | 1.438 s   | 3.152 s   |
| ring_vk_builder_append | 15.2 ms   | 48.4 ms   | 80.4 ms   |
| ring_vk_builder_finalize | 99.6 ns | 108.9 ns  | 104.7 ns  |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 273 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 50.8 us  | 97.7 us  | 214.6 us | 426.5 us | 888.5 us | 1.77 ms  | 3.52 ms  | 7.04 ms  | 13.2 ms  |
| batch_prepare_seq  | 41.3 us  | 89.4 us  | 179.7 us | 388.0 us | 803.9 us | 1.67 ms  | 3.26 ms  | 6.65 ms  | 13.5 ms  |
| batch_prepare_par  | 49.1 us  | 73.6 us  | 115.2 us | 154.6 us | 212.6 us | 236.3 us | 225.7 us | 468.4 us | 768.2 us |
| batch_push_prepared| 5.3 us   | 9.9 us   | 19.8 us  | 38.8 us  | 74.0 us  | 145.0 us | 271.9 us | 526.7 us | 1.07 ms  |
| batch_verify       | 3.48 ms  | 4.38 ms  | 5.98 ms  | 8.63 ms  | 12.7 ms  | 20.8 ms  | 32.3 ms  | 57.5 ms  | 100.0 ms |

## Straus MSM (`straus.rs`)

Windowed Straus multi-scalar multiplication for small point counts.
The table shows times for the bandersnatch suite.

| n\w | w=1       | w=2       | w=3       | w=4       |
|----:|----------:|----------:|----------:|----------:|
|   2 | 118.4 us  | 90.5 us   | 98.0 us   | 161.8 us  |
|   3 | 121.5 us  | 107.4 us  | 270.3 us  | 1.65 ms   |
|   4 | 125.5 us  | 181.6 us  | 1.66 ms   | 25.1 ms   |
|   5 | 130.6 us  | 481.7 us  | 12.5 ms   | 534.7 ms  |

Table size is (2^w)^n, so the cost grows combinatorially in w for a given n.
Optimal window size is w=2 for n=2 and w=1 for n>=3.

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.2 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 150 ms at n=255, 481 ms at n=1023,
  810 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.2 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-109 ns).
- `ring_context_setup` and `ring_params_setup` have identical cost (~0.85 ms at n=255,
  ~3.6 ms at n=1023, ~8.4 ms at n=2047), confirming that `RingContext` construction
  is dominated by PIOP domain setup with no SRS overhead.

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (273 us) + n * `ring_verify` (3.27 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~41 us/proof) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit gives ~3.1 ms base + ~0.38 ms per additional proof.
The ring multi-pairing marginal cost is ~0.35 ms/proof; the Pedersen MSM adds
~0.03 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.38 ms (verify) = ~0.43 ms,
or ~7.6x cheaper than simple verification (3.27 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.38 ms marginal, or ~8.6x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.54 ms  |    3.52 ms  |    3.53 ms  |         1.01x |         1.00x |
|   2 |    6.81 ms  |    4.47 ms  |    4.45 ms  |         1.52x |         1.53x |
|   4 |   13.35 ms  |    6.16 ms  |    6.10 ms  |         2.17x |         2.19x |
|   8 |   26.43 ms  |    9.02 ms  |    8.78 ms  |         2.93x |         3.01x |
|  16 |   52.59 ms  |   13.52 ms  |   12.93 ms  |         3.89x |         4.07x |
|  32 |  104.91 ms  |   22.47 ms  |   21.04 ms  |         4.67x |         4.99x |
|  64 |  209.55 ms  |   36.77 ms  |   32.52 ms  |         5.70x |         6.44x |
| 128 |  418.83 ms  |   64.15 ms  |   57.96 ms  |         6.53x |         7.23x |
| 256 |  837.39 ms  |  113.50 ms  |  100.77 ms  |         7.38x |         8.31x |

### Batch Verify Scaling

The `batch_verify` step scales sublinearly in the number of proofs:

| n   | batch_verify | per-proof |
|----:|-----------:|----------:|
|   1 |    3.48 ms |  3.48 ms  |
|   2 |    4.38 ms |  2.19 ms  |
|   4 |    5.98 ms |  1.50 ms  |
|   8 |    8.63 ms |  1.08 ms  |
|  16 |   12.7 ms  |  0.79 ms  |
|  32 |   20.8 ms  |  0.65 ms  |
|  64 |   32.3 ms  |  0.50 ms  |
| 128 |   57.5 ms  |  0.45 ms  |
| 256 |  100.0 ms  |  0.39 ms  |

Amortized cost per proof drops from 3.48 ms (n=1) to 0.39 ms (n=256), roughly 8.9x.
Two factors contribute: the fixed-cost ring multi-pairing base (~3.5 ms) amortized
across all proofs, and the MSM itself which scales as O(n / log n) via
Pippenger/bucket methods rather than O(n).
