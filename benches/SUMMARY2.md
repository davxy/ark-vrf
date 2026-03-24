# Benchmark Baseline

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-03-24
Features: `bandersnatch`, `ring`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: 11th Gen Intel Core i7-1185G7 @ 3.00 GHz (4 cores / 8 threads)
- RAM: 32 GB DDR4
- OS: Arch Linux, kernel 6.19.6
- Rust: 1.91.1 (ed61e7d7e 2025-11-07)

## Common Operations (`common.rs`)

| Benchmark                    |     Time |
|:-----------------------------|---------:|
| vrf_output                   | 77.7 us  |
| data_to_point_tai            | 19.4 us  |
| data_to_point_ell2           | 65.2 us  |
| point_to_hash                | 603 ns   |
| challenge                    | 1.13 us  |
| nonce_rfc_8032               | 2.07 us  |

## IETF VRF Operations (`ietf.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| ietf_prove             | 156.6 us |
| ietf_verify            | 272.4 us |

## Pedersen VRF Operations (`pedersen.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| pedersen_prove         | 391.1 us |
| pedersen_verify        | 396.1 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.35 us  | 2.40 us  | 4.80 us  | 10.9 us  | 22.4 us  | 43.7 us  | 89.1 us  | 159.6 us | 365.9 us |
| batch_verify         | 604.2 us | 627.2 us | 926.5 us | 2.21 ms  | 2.37 ms  | 4.61 ms  | 6.98 ms  | 9.66 ms  | 20.2 ms  |

## Thin VRF Operations (`thin.rs`)

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 251.9 us |
| thin_verify            | 294.5 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.99 us  | 4.20 us  | 8.51 us  | 15.0 us  | 34.9 us  | 62.8 us  | 147.8 us | 296.1 us | 603.3 us |
| batch_verify         | 540.5 us | 565.7 us | 717.1 us | 1.97 ms  | 2.37 ms  | 4.26 ms  | 7.27 ms  | 8.72 ms  | 15.7 ms  |

## Ring VRF Operations (`ring.rs`)

| Benchmark              | n=255     | n=1023    | n=2047    |
|:-----------------------|----------:|----------:|----------:|
| ring_params_setup      | 0.94 ms   | 4.32 ms   | 10.1 ms   |
| ring_prover_key        | 52.4 ms   | 156.1 ms  | 299.8 ms  |
| ring_verifier_key      | 52.8 ms   | 163.8 ms  | 262.1 ms  |
| ring_prove             | 153.2 ms  | 501.5 ms  | 1.012 s   |
| ring_verify            | 3.55 ms   | 3.92 ms   | 3.88 ms   |
| ring_verifier_from_key | 257.3 us  | 331.4 us  | 337.1 us  |
| ring_vk_from_commitment| 56.2 ns   | 64.5 ns   | 63.7 ns   |
| ring_vk_builder_create | 360.4 ms  | 1.536 s   | 3.599 s   |
| ring_vk_builder_append | 18.4 ms   | 55.0 ms   | 86.3 ms   |
| ring_vk_builder_finalize | 79.6 ns | 79.9 ns   | 75.4 ns   |

### Batch Verification (ring size = 1023)

| Benchmark          | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:-------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_verifier_new | 363 us   | -        | -        | -        | -        | -        | -        | -        | -        |
| batch_push         | 60.4 us  | 123.0 us | 255.0 us | 527.7 us | 1.06 ms  | 2.22 ms  | 3.79 ms  | 8.91 ms  | 17.2 ms  |
| batch_prepare_seq  | 51.8 us  | 107.2 us | 223.4 us | 475.1 us | 993.8 us | 1.73 ms  | 3.93 ms  | 7.01 ms  | 14.6 ms  |
| batch_prepare_par  | 55.7 us  | 79.0 us  | 114.2 us | 146.3 us | 265.0 us | 545.9 us | 1.11 ms  | 2.10 ms  | 4.20 ms  |
| batch_push_prepared| 6.1 us   | 12.5 us  | 23.0 us  | 47.5 us  | 92.5 us  | 179.9 us | 367.9 us | 645.7 us | 1.44 ms  |
| batch_verify       | 4.53 ms  | 5.49 ms  | 6.85 ms  | 11.3 ms  | 14.8 ms  | 28.1 ms  | 44.3 ms  | 74.7 ms  | 123.4 ms |

## Straus MSM (`straus.rs`)

| n \ w |    w=1    |    w=2    |    w=3    |    w=4     |
|------:|----------:|----------:|----------:|-----------:|
|     2 | 167.0 us  | 132.3 us  | 143.6 us  | 243.9 us   |
|     3 | 171.0 us  | 157.5 us  | 389.1 us  | 2.49 ms    |
|     4 | 179.8 us  | 262.4 us  | 2.53 ms   | 45.9 ms    |
|     5 | 188.3 us  | 718.7 us  | 20.2 ms   | 784.6 ms   |

The optimal window size depends on the number of points n. The table has (2^w)^n
entries, so it grows exponentially in both w and n. For each n, the best w is
the one where the reduced iteration count still outweighs the table construction
cost:

- n=2: **w=2** is optimal (132 us). w=3 is close (144 us) but the 64-entry table
  starts to cost more than the iteration savings. w=1 is 27% slower.
- n=3: **w=2** is optimal (158 us). w=1 is only 8% slower (171 us), while w=3
  already suffers from a 512-entry table (389 us).
- n=4: **w=1** is optimal (180 us). w=2 is 46% slower (262 us) due to its
  256-entry table. w=3 and w=4 are dominated by table construction.
- n=5: **w=1** is optimal (188 us). w=2 is already 3.8x slower (719 us) with
  its 1024-entry table.

In short: w=2 wins for n<=3, w=1 wins for n>=4. Beyond n=3, the exponential
table cost makes any w>1 impractical.
