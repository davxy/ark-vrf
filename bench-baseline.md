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
