# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-25

### Fixed

- **Security**: Bind additional data (`ad`) to nonce derivation. Previously, nonces
  depended only on the secret key and input point, allowing secret key recovery from
  two proofs over the same input with different additional data. Affects all schemes.

### Changed

- `Suite::nonce` signature now takes an additional `ad: &[u8]` parameter.
  This is a breaking change for custom `Suite` implementations that override `nonce`.

## [0.2.1] - 2026-02-19

### Changed

- Bump `w3f-ring-proof` dependency to 0.0.6.

### Removed

- `RingProofParams::clone_verifier_key` workaround, no longer needed as
  upstream `RingVerifierKey` now implements `Clone`.

## [0.2.0] - 2026-02-18

### Added

- Ring proof batch verification using random linear combination.
- Pedersen proof batch verification with 5N+2 point MSM.
- Domain size conversion utilities for ring proof parameters.
- Constant encoded lengths in codec for all proof and signature types.
- Comprehensive benchmarks for all VRF schemes (IETF, Pedersen, Ring).

### Changed

- `Input::from(Affine)` renamed to `Input::from_affine(Affine)`.
- Secret scalar field is now private.

### Fixed

- RFC-6979 nonce generation.

## [0.1.1] - 2025-12-12

### Added

- `secret-split` feature: scalar multiplication with secret split for side-channel
  defense. Secret scalar is split into the sum of two randomly mutating scalars.
- Ring verifier key builder for incremental ring construction.
- Optional cofactor clearing for RFC-9381 `hash_to_curve`.
- Unlocked `sha2` assembly feature.

### Changed

- Bump Rust edition to 2024.
- Improved secret scalar generation.
- Simplified ring proof trait bounds using associated type bounds.

## [0.1.0] - 2025-03-28

### Added

- IETF VRF compliant with RFC-9381 (ECVRF).
- Pedersen VRF with key-hiding properties.
- Ring VRF with signer anonymity using zk-SNARK membership proofs.
- Built-in suites: Ed25519, Secp256r1, Bandersnatch, JubJub, Baby-JubJub.
- Elligator 2 and Try-and-Increment hash-to-curve strategies.
- RFC-6979 deterministic nonce generation (optional).
- Codec trait for customizable serialization formats.
- Test vectors for all suites and schemes.
- `no_std` support.
- `parallel` and `asm` optimization features.

[0.3.0]: https://github.com/davxy/ark-vrf/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/davxy/ark-vrf/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/davxy/ark-vrf/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/davxy/ark-vrf/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/davxy/ark-vrf/releases/tag/v0.1.0
