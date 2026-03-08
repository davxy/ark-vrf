# Thin VRF Benchmark

Suite: Bandersnatch SHA-512 ELL2 (Twisted Edwards on BLS12-381)
Date: 2026-03-08
Features: `bandersnatch`, `asm` (no `parallel`)
Criterion: `--quick` mode

## Machine

- CPU: AMD Ryzen Threadripper 3970X 32-Core (64 threads @ 3.7 GHz base, 4.5 GHz boost)
- RAM: 64 GB DDR4
- OS: Arch Linux, kernel 6.19.6
- Rust: 1.91.1 (ed61e7d7e 2025-11-07)

## Thin VRF Operations

| Benchmark              |     Time |
|:-----------------------|---------:|
| thin_prove             | 267.2 us |
| thin_verify            | 315.2 us |

### Batch Verification

| Benchmark            | n=1      | n=2      | n=4      | n=8      | n=16     | n=32     | n=64     | n=128    | n=256    |
|:---------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| batch_prepare        | 1.47 us  | 3.08 us  | 5.95 us  | 11.40 us | 25.76 us | 49.82 us | 103.8 us | 215.1 us | 526.4 us |
| batch_verify         | 500.0 us | 611.2 us | 803.2 us | 1.88 ms  | 2.22 ms  | 3.81 ms  | 7.14 ms  | 9.59 ms  | 16.15 ms |
