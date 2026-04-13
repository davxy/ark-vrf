# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - Unreleased

### Added

- `RingContext` struct for lightweight ring proof parameter caching.
  Contains only the PIOP parameters needed for prover/verifier instance
  construction, without the KZG SRS required for key construction.
- Multi-ring batch verification: a single `ring::BatchVerifier` can now
  aggregate proofs from multiple rings sharing the same KZG SRS into one
  batched pairing check.
- `ring::BatchItem::new(verifier, ios, ad, proof)` and
  `pedersen::BatchItem::new(ios, ad, proof)` constructors for preparing
  batch items independently of any verifier instance.

### Changed

- `RingProofParams` renamed to `RingSetup`.

### Removed

- `RingProofParams::verifier_no_context` method, superseded by
  `RingContext::new`.
- `ring::BatchVerifier::prepare` and `pedersen::BatchVerifier::prepare`,
  superseded by `BatchItem::new` constructors.

## [0.4.0] - 2026-04-02

This release follows
[draft-33](https://github.com/davxy/bandersnatch-vrf-spec/releases/tag/draft-33)
of the Bandersnatch VRF specification.

### Changed

- Renamed IETF VRF to **Tiny VRF**. The scheme now uses a single nonce commitment
  `R = k * I_m` on the delinearized merged input rather than separate commitments
  for the generator and each VRF input.
- Thin VRF is now described as a variant of Tiny VRF that stores the nonce
  commitment `R` instead of the challenge `c`, enabling batch verification at the
  cost of a slightly larger proof.
- Updated all test vectors to reflect the new Tiny VRF proof structure.

### Removed

- `Blake3Transcript` and the `blake3` feature/dependency.
- `bandersnatch_blake3` suite (including its test vectors).

## [0.3.0] - 2026-03-28

This release follows
[draft-32](https://github.com/davxy/bandersnatch-vrf-spec/releases/tag/draft-32)
of the Bandersnatch VRF specification.

### Added

- Pluggable `Transcript` trait for Fiat-Shamir transform, replacing the previous
  hard-coded hash constructions. Provided implementations: `HashTranscript` (SHA-512,
  SHA-256 via counter-mode XOF), `Blake3Transcript`, `Shake128Transcript`.
- `Suite::Transcript` associated type. Nonce generation, challenge derivation,
  and other hash-based operations now go through the transcript abstraction.
- Thin VRF scheme. Merges the Schnorr public-key and VRF I/O DLEQ into a
  single delinearized relation with a Schnorr-like proof (R, s). Supports batch
  verification via randomized multi-scalar multiplication.
- Multi-input IETF VRF using delinearized DLEQ. Proves multiple input-output
  pairs with a single proof via `delinearize` folding. N=1 is byte-identical
  to single-pair proving. N=0 reduces to a Schnorr signature over additional data.
- Straus multi-scalar multiplication (`utils::straus::short_msm`) for small
  point counts (n=2..5), with configurable window size. Used in IETF, Pedersen,
  and Thin VRF verification to replace independent scalar multiplications.

### Fixed

- Challenge serialization now validates that the value fits in `CHALLENGE_LEN`,
  rejecting proofs with oversized challenge values.

### Changed

- `Suite` trait now requires a `Transcript` associated type and `nonce`/`challenge`
  methods use the transcript rather than raw hash functions. This is a breaking change
  for custom `Suite` implementations.
- Removed `CHALLENGE_LEN` from the `Suite` trait; it is now a module-level constant
  (`utils::common::CHALLENGE_LEN`) fixed at 16 bytes (128-bit security).
- Challenge and blinding factor decoding now use suite codec (`scalar_decode`)
  instead of `from_be_bytes_mod_order`, so endianness follows the suite configuration.

## [0.2.2] - 2026-03-17

### Changed

- Nonce derivation now binds additional data (`ad`), preventing secret key
  recovery from two proofs over the same input with different `ad`. In the
  IETF scheme `ad` is included directly; in the Pedersen scheme the two secrets
  are cross-bound: `k` nonce includes `blinding || ad`, `kb` nonce includes
  `secret || ad`.

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

[0.4.0]: https://github.com/davxy/ark-vrf/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/davxy/ark-vrf/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/davxy/ark-vrf/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/davxy/ark-vrf/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/davxy/ark-vrf/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/davxy/ark-vrf/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/davxy/ark-vrf/releases/tag/v0.1.0
