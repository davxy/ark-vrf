# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-02-13
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)

## VRF Operations

| Benchmark              |     Time |
|:-----------------------|---------:|
| key_from_seed          | 122.7 us |
| hash_to_curve          | 100.8 us |
| vrf_output             | 126.5 us |
| output_hash            | 566.0 ns |
| nonce_generation       | 3.62 us  |
| challenge_generation   | 1.46 us  |
| ietf_prove             | 246.0 us |
| ietf_verify            | 492.8 us |
| pedersen_prove         | 674.5 us |
| pedersen_verify        | 630.5 us |

## Ring Operations

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 1.20 ms   | 6.17 ms   | 12.71 ms  |
| ring_prover_key        | 64.0 ms   | 192.0 ms  | 363.8 ms  |
| ring_verifier_key      | 62.7 ms   | 192.9 ms  | 354.1 ms  |
| ring_prove             | 208.2 ms  | 670.1 ms  | 1.271 s   |
| ring_verify            | 4.97 ms   | 5.00 ms   | 4.95 ms   |
| ring_verifier_from_key | 400.3 us  | 387.8 us  | 456.9 us  |
| ring_vk_from_commitment| 80.3 ns   | 80.9 ns   | 79.2 ns   |
| ring_vk_builder_create | 445.0 ms  | 2.044 s   | 4.444 s   |
| ring_vk_builder_append | 23.4 ms   | 65.5 ms   | 119.0 ms  |
| ring_vk_builder_finalize | 92.8 ns | 94.5 ns   | 93.2 ns   |

## Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 421 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 793 us   | 1.67 ms  | 3.09 ms  | 5.97 ms  | 12.3 ms  | 23.7 ms  | 47.2 ms  | 100.8 ms | 189.2 ms |
| batch_prepare_seq  | 680 us   | 1.43 ms  | 3.40 ms  | 7.35 ms  | 11.6 ms  | 26.4 ms  | 48.9 ms  | 97.5 ms  | 188.7 ms |
| batch_prepare_par  | 697 us   | 1.28 ms  | 1.50 ms  | 2.69 ms  | 4.09 ms  | 7.45 ms  | 14.6 ms  | 28.2 ms  | 54.4 ms  |
| batch_push_prepared| 8.4 us   | 15.8 us  | 30.0 us  | 55.8 us  | 134 us   | 205 us   | 418 us   | 831 us   | 1.56 ms  |
| batch_verify       | 4.10 ms  | 5.57 ms  | 7.28 ms  | 10.3 ms  | 15.3 ms  | 23.4 ms  | 38.9 ms  | 63.9 ms  | 112.5 ms |

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (~5.0 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 208 ms at n=255, 670 ms at n=1023,
  1.27 s at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 4.4 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (388 us) + n * `ring_verify` (5.00 ms).

Batch verification combines multiple pairing checks into a single multi-pairing.
A linear fit on `batch_verify` gives ~3.7 ms base + ~0.43 ms per additional proof,
compared to 5.00 ms per proof for individual verification. Each extra proof in a
batch costs ~12x less on the verify step alone.

The `push`/`prepare` step (~740 us per proof) cannot be batched, giving a total
sequential marginal cost of ~1.17 ms per proof (0.43 + 0.74), or ~4.3x cheaper
than simple verification. With parallel prepare, the per-proof prepare cost drops
to ~213 us at n=256, giving ~0.64 ms marginal, or ~7.8x cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    5.39 ms  |    5.31 ms  |    5.23 ms  |         1.02x |         1.03x |
|   2 |   10.39 ms  |    7.66 ms  |    7.29 ms  |         1.36x |         1.43x |
|   4 |   20.39 ms  |   10.79 ms  |    9.23 ms  |         1.89x |         2.21x |
|   8 |   40.39 ms  |   16.69 ms  |   13.47 ms  |         2.42x |         3.00x |
|  16 |   80.39 ms  |   28.02 ms  |   19.95 ms  |         2.87x |         4.03x |
|  32 |  160.39 ms  |   47.52 ms  |   31.48 ms  |         3.37x |         5.09x |
|  64 |  320.39 ms  |   86.52 ms  |   54.34 ms  |         3.70x |         5.90x |
| 128 |  640.39 ms  |  165.12 ms  |   93.35 ms  |         3.88x |         6.86x |
| 256 | 1280.39 ms  |  302.12 ms  |  168.88 ms  |         4.24x |         7.58x |
