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
| ring_params_setup      | 0.84 ms   | 3.71 ms   | 8.38 ms   |
| ring_prover_key        | 43.8 ms   | 125.8 ms  | 247.9 ms  |
| ring_verifier_key      | 43.5 ms   | 125.8 ms  | 244.7 ms  |
| ring_prove             | 147.0 ms  | 462.0 ms  | 821.0 ms  |
| ring_verify            | 3.50 ms   | 3.25 ms   | 3.46 ms   |
| ring_verifier_from_key | 255.6 us  | 284.0 us  | 306.5 us  |
| ring_vk_from_commitment| 72.2 ns   | 73.4 ns   | 71.3 ns   |
| ring_vk_builder_create | 305.5 ms  | 1.392 s   | 3.173 s   |
| ring_vk_builder_append | 16.2 ms   | 47.7 ms   | 78.5 ms   |
| ring_vk_builder_finalize | 108.5 ns | 108.4 ns  | 110.7 ns  |

## Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 267 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 459 us   | 1.08 ms  | 1.86 ms  | 3.95 ms  | 7.30 ms  | 15.6 ms  | 29.3 ms  | 59.3 ms  | 125.5 ms |
| batch_prepare_seq  | 440 us   | 906 us   | 1.80 ms  | 3.89 ms  | 7.26 ms  | 16.4 ms  | 28.9 ms  | 58.4 ms  | 124.2 ms |
| batch_prepare_par  | 445 us   | 587 us   | 712 us   | 806 us   | 994 us   | 1.37 ms  | 1.88 ms  | 3.05 ms  | 4.30 ms  |
| batch_push_prepared| 5.3 us   | 9.8 us   | 20.3 us  | 35.7 us  | 75.7 us  | 130 us   | 275 us   | 624 us   | 1.28 ms  |
| batch_verify       | 3.06 ms  | 3.43 ms  | 5.03 ms  | 6.31 ms  | 10.2 ms  | 15.9 ms  | 24.8 ms  | 43.2 ms  | 80.9 ms  |

## Notes

### Ring Operations

- `ring_verify` is roughly constant across ring sizes (≈3.3-3.5 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 147 ms at n=255, 462 ms at n=1023,
  821 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.2 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-111 ns).

### Batch Verification vs Simple Verification

Simple verification cost for n proofs (ring size 1023):
`ring_verifier_from_key` (284 us) + n * `ring_verify` (3.25 ms).

Batch verification combines multiple pairing checks into a single multi-pairing.
A linear fit on `batch_verify` gives ≈2.8 ms base + ≈0.31 ms per additional proof,
compared to 3.25 ms per proof for individual verification. Each extra proof in a
batch costs ≈10x less on the verify step alone.

The `push`/`prepare` step (≈490 us per proof) cannot be batched, giving a total
sequential marginal cost of ≈0.80 ms per proof (0.31 + 0.49), or ≈4.1x cheaper
than simple verification. With parallel prepare, the per-proof prepare cost drops
to ≈17 us at n=256, giving ≈0.33 ms marginal, or ≈10x cheaper.

Estimated total wall times and speedups:

| n   | Simple      | Batch seq   | Batch par   | Speedup (seq) | Speedup (par) |
|----:|------------:|------------:|------------:|--------------:|--------------:|
|   1 |    3.53 ms  |    3.79 ms  |    3.78 ms  |         0.93x |         0.93x |
|   2 |    6.78 ms  |    4.78 ms  |    4.29 ms  |         1.42x |         1.58x |
|   4 |   13.28 ms  |    7.16 ms  |    6.03 ms  |         1.85x |         2.20x |
|   8 |   26.28 ms  |   10.53 ms  |    7.42 ms  |         2.50x |         3.54x |
|  16 |   52.28 ms  |   17.76 ms  |   11.53 ms  |         2.94x |         4.53x |
|  32 |  104.28 ms  |   31.76 ms  |   17.70 ms  |         3.28x |         5.89x |
|  64 |  208.28 ms  |   54.35 ms  |   27.20 ms  |         3.83x |         7.66x |
| 128 |  416.28 ms  |  102.81 ms  |   47.17 ms  |         4.05x |         8.83x |
| 256 |  832.28 ms  |  206.64 ms  |   86.76 ms  |         4.03x |         9.59x |
