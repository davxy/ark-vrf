# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-02-13
Features: `bandersnatch`, `ring` (no `parallel`, no `asm`)

## VRF Operations

| Benchmark              |     Time |
|:-----------------------|---------:|
| key_from_seed          | 92.9 us  |
| hash_to_curve          | 74.9 us  |
| vrf_output             | 96.0 us  |
| output_hash            | 408.8 ns |
| nonce_generation       | 2.59 us  |
| challenge_generation   | 1.15 us  |
| ietf_prove             | 218.6 us |
| ietf_verify            | 381.8 us |
| pedersen_prove         | 576.5 us |
| pedersen_verify        | 538.9 us |

## Ring Operations

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 939.9 us  | 5.08 ms   | 10.55 ms  |
| ring_prover_key        | 62.85 ms  | 143.1 ms  | 280.9 ms  |
| ring_verifier_key      | 47.77 ms  | 150.4 ms  | 264.3 ms  |
| ring_prove             | 155.0 ms  | 504.3 ms  | 988.8 ms  |
| ring_verify            | 3.74 ms   | 3.89 ms   | 3.82 ms   |
| ring_verifier_from_key | 264.5 us  | 317.0 us  | 393.9 us  |
| ring_vk_from_commitment| 68.2 ns   | 71.8 ns   | 68.6 ns   |
| ring_vk_builder_create | 339.5 ms  | 1.644 s   | 3.391 s   |
| ring_vk_builder_append | 17.45 ms  | 52.74 ms  | 86.62 ms  |
| ring_vk_builder_finalize | 76.1 ns | 76.3 ns   | 75.3 ns   |

## Notes

- VRF scalar multiplication cost dominates: each mul is ~95 us. IETF prove (~2 muls)
  at 219 us, IETF verify (~4 muls) at 382 us, Pedersen prove (~5 muls) at 577 us,
  Pedersen verify (~6 muls) at 539 us are all consistent with this.
- `ring_verify` is roughly constant across ring sizes (~3.7-3.9 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 155 ms at n=255, 504 ms at n=1023,
  989 ms at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.4 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
