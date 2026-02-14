# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-02-14
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.18.8
- Rust: 1.93.0 (254b59607 2026-01-19)

## VRF Operations

| Benchmark              |     Time |
|:-----------------------|---------:|
| key_from_seed          | 83.6 us  |
| hash_to_curve          | 73.6 us  |
| vrf_output             | 82.7 us  |
| output_hash            | 411.4 ns |
| nonce_generation       | 2.38 us  |
| challenge_generation   | 1.02 us  |
| ietf_prove             | 175.9 us |
| ietf_verify            | 354.0 us |
| pedersen_prove         | 466.9 us |
| pedersen_verify        | 451.7 us |

## Ring Operations

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.79 ms   | 3.64 ms   | 7.80 ms   |
| ring_prover_key        | 47.3 ms   | 129.3 ms  | 233.6 ms  |
| ring_verifier_key      | 44.2 ms   | 128.7 ms  | 244.2 ms  |
| ring_prove             | 151.6 ms  | 479.6 ms  | 849.8 ms  |
| ring_verify            | 3.52 ms   | 3.48 ms   | 3.52 ms   |
| ring_verifier_from_key | 252.7 us  | 274.4 us  | 302.2 us  |
| ring_vk_from_commitment| 71.8 ns   | 72.4 ns   | 71.8 ns   |
| ring_vk_builder_create | 318.3 ms  | 1.455 s   | 3.208 s   |
| ring_vk_builder_append | 16.3 ms   | 48.7 ms   | 81.4 ms   |
| ring_vk_builder_finalize | 97.7 ns | 105.5 ns  | 97.7 ns   |

## Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 258 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 51.8 us  | 97.4 us  | 215.8 us | 433.5 us | 826.6 us | 1.66 ms  | 3.34 ms  | 6.63 ms  | 14.4 ms  |
| batch_prepare_seq  | 40.8 us  | 82.8 us  | 182.4 us | 361.5 us | 754.5 us | 1.53 ms  | 3.38 ms  | 6.10 ms  | 12.3 ms  |
| batch_prepare_par  | 41.1 us  | 69.0 us  | 107.8 us | 157.9 us | 239.7 us | 248.6 us | 233.1 us | 474.0 us | 823.0 us |
| batch_push_prepared| 5.2 us   | 10.5 us  | 19.8 us  | 39.8 us  | 69.9 us  | 171.7 us | 268.0 us | 543.2 us | 1.14 ms  |
| batch_verify       | 3.27 ms  | 4.43 ms  | 5.95 ms  | 8.14 ms  | 12.1 ms  | 19.95 ms | 31.67 ms | 56.9 ms  | 93.2 ms  |

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~3.5 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 152 ms at n=255, 480 ms at n=1023,
  850 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.2 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-106 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (274 us) + n * `ring_verify` (3.48 ms).

Batch verification combines multiple pairing checks into a single multi-pairing
(ring proof) and multiple Pedersen verifications into a single (5N+2)-point MSM.

The `prepare` step (~48 us/proof) computes only the Pedersen challenge hash and
packages data for deferred verification -- no scalar multiplications. The Pedersen
verification is deferred to `verify`, where it runs as a single batched MSM using
random linear combination with independent random scalars per equation.

The `verify` step includes both the ring batch multi-pairing and the Pedersen
batch MSM. A linear fit gives ~2.9 ms base + ~0.35 ms per additional proof.
The ring multi-pairing marginal cost is ~0.31 ms/proof; the Pedersen MSM adds
~0.04 ms/proof amortized.

Sequential marginal cost per proof: ~0.05 ms (prepare) + ~0.35 ms (verify) = ~0.40 ms,
or ~8.7x cheaper than simple verification (3.48 ms). With parallel prepare, the
per-proof prepare cost drops to ~3 us at n=256, giving ~0.35 ms marginal, or ~10x
cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.75 ms  |    3.32 ms  |    3.31 ms  |         1.13x |         1.13x |
|   2 |    7.23 ms  |    4.53 ms  |    4.51 ms  |         1.60x |         1.60x |
|   4 |   14.19 ms  |    6.17 ms  |    6.08 ms  |         2.30x |         2.33x |
|   8 |   28.11 ms  |    8.57 ms  |    8.34 ms  |         3.28x |         3.37x |
|  16 |   55.95 ms  |   12.93 ms  |   12.41 ms  |         4.33x |         4.51x |
|  32 |  111.63 ms  |   21.61 ms  |   20.37 ms  |         5.16x |         5.48x |
|  64 |  223.00 ms  |   35.01 ms  |   32.17 ms  |         6.37x |         6.93x |
| 128 |  445.70 ms  |   63.55 ms  |   57.93 ms  |         7.01x |         7.69x |
| 256 |  891.15 ms  |  107.60 ms  |   95.12 ms  |         8.28x |         9.37x |

### Effect of Batched Pedersen Verification

The Pedersen batch MSM replaces N individual 5-point verifications (~452 us each)
with a single (5N+2)-point MSM during `verify`. This shifts cost from `prepare`
to `verify`:

| Metric (n=256)   | Before      | After       | Change       |
|:------------------|------------:|------------:|:-------------|
| prepare_seq       | 124.2 ms    | 12.3 ms     | 10.1x faster |
| prepare_par       | 4.30 ms     | 0.82 ms     | 5.2x faster  |
| batch_verify      | 80.9 ms     | 93.2 ms     | 15% slower   |
| Total (seq)       | 206.4 ms    | 107.6 ms    | 1.92x faster |
| Total (par)       | 86.5 ms     | 95.1 ms     | ~same        |

The sequential pipeline benefits most: prepare drops from ~490 us/proof to ~48 us/proof,
while the additional MSM cost in verify (~12 ms at n=256) is much smaller than the
savings. The parallel pipeline sees less net gain since prepare was already cheap
when parallelized, and the verify increase slightly offsets the savings.
