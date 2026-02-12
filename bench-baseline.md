# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-02-12
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
| ring_params_setup      | 1.02 ms   | 4.87 ms   | 11.77 ms  |
| ring_prover_key        | 51.36 ms  | 163.03 ms | 309.19 ms |
| ring_verifier_key      | 49.34 ms  | 161.80 ms | 301.28 ms |
| ring_prove             | 168.19 ms | 543.06 ms | 1.013 s   |
| ring_verify            | 4.85 ms   | 4.47 ms   | 4.61 ms   |
| ring_verifier_from_key | 310.3 us  | 355.5 us  | 398.7 us  |
| ring_vk_from_commitment| 71.8 ns   | 66.8 ns   | 64.4 ns   |
| ring_vk_builder_create | 376.80 ms | 1.578 s   | 3.652 s   |
| ring_vk_builder_append | 18.68 ms  | 50.45 ms  | 95.06 ms  |
| ring_vk_builder_finalize | 83.7 ns | 83.2 ns   | 75.1 ns   |

## Notes

- VRF scalar multiplication cost dominates: each mul is ~95 us. IETF prove (~2 muls)
  at 219 us, IETF verify (~4 muls) at 382 us, Pedersen prove (~5 muls) at 577 us,
  Pedersen verify (~6 muls) at 539 us are all consistent with this.
- `ring_verify` is roughly constant across ring sizes (~4.5-4.9 ms) since verification
  cost depends on the PIOP domain size, which stays the same for all three sizes tested
  (they all round up to the same power-of-two domain).
- `ring_prove` scales linearly with ring size: 168 ms at n=255, 543 ms at n=1023,
  1.01 s at n=2047.
- `ring_vk_builder_create` is the most expensive operation (up to 3.7 s at n=2047).
  This is the Lagrangian SRS computation.
- `ring_vk_builder_finalize` and `ring_vk_from_commitment` are essentially free
  (sub-100 ns).
