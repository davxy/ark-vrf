# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking**: `Public`, `Input` and `Output` are now aliases of the generic
  `PointWrapper<S, K>` with a private point field. Construct them with
  `from_affine`, `from_affine_unchecked`, `Input::new` or deserialization.
- **Breaking**: `thin::BatchVerifier::prepare` replaced by
  `thin::BatchItem::new(public, ios, ad, proof)`, matching the Pedersen and
  ring batch APIs.
- **Breaking**: proof types are opaque. The fields of `tiny::Proof`,
  `thin::Proof` and `ring::Proof` are no longer public, matching
  `pedersen::Proof`. Construct proofs with `prove` or by deserialization, so
  every proof holds subgroup-checked points unless built with a
  `deserialize_*_unchecked` method.
- **Breaking**: `Input::new` returns `Result<Self, Error>` instead of
  `Option<Self>`, like the other checked constructors. A failed hash-to-curve
  is `Error::InvalidData`.
- **Breaking**: `PointWrapper` no longer implements `Deref` to the affine
  point. Read it with the new `point()` method. The wrappers are role types,
  not smart pointers.
- **Breaking**: `Suite::nonce`, `Suite::challenge`, `utils::nonce` and
  `utils::challenge` take the transcript directly instead of an `Option`,
  like `PedersenSuite::blinding`.
- **Breaking**: `RingSetup` no longer implements `Deref` to `RingContext`.
  Use `ring_context()`. The `pcs_params` and `ring_ctx` fields are private;
  `pcs_params()` and `ring_context()` read them. A setup now always comes
  from a constructor or from decoding, so its SRS has the shape its context
  needs and its encoding decodes to its own domain. Before, a struct literal
  could pair an SRS of one domain with a context of another, and the bytes
  of such a setup decoded to another domain, or not at all.
- **Breaking**: `RingContext::piop_params` is private; `piop_params()` reads
  it. The capacity checks of `prover_key`, `verifier_key` and `ring_prover`
  read the context, so a context now always comes from `new`,
  `new_without_blinding` or a setup.
- **Breaking**: `ring::max_ring_size_from_piop_domain_size`,
  `ring::piop_domain_size_from_pcs_domain_size` and
  `ring::max_ring_size_from_pcs_domain_size` return `Option<usize>`. `None`
  means that no valid domain fits the given size. Before, such inputs
  panicked or wrapped. A domain that holds no key, one not larger than the
  PIOP overhead, is `None` too.
- The `smul!` macro is crate-private. It was exported as `#[doc(hidden)]`.
- `Secret` hardening: the Tiny, Thin and Pedersen provers zeroize their
  nonces and challenge products, the ring prover zeroizes its copy of the
  blinding factor, and `secret-split` zeroizes the split scalars. Key
  derivation already did this since 0.5.3.
- `secret-split` also covers public key derivation in `Secret::from_scalar`,
  which runs on every `Secret` deserialization.
- The counter-mode XOF reader behind `HashTranscript` zeroizes its seed and
  output block on drop, and the nonce reduction buffer is zeroized. The
  `digest` 0.10 hasher state cannot be zeroized; see the `DigestXof` docs.

### Fixed

- `Suite::Affine` docs claimed that the `AffineRepr` bound guarantees
  prime-order subgroup membership. It does not; the checked constructors and
  checked deserialization of the point wrappers do.
- `utils::nonce` docs said the upper half of the expanded key is absorbed.
  All 64 bytes are.
- `RingSetup::prover_key`, `RingSetup::verifier_key` and
  `VerifierKeyBuilder::append` return `Error::InvalidData` for a member key
  equal to the identity. On Twisted Edwards suites the identity reached an
  assertion in the ring proof backend and panicked.
- `RingContext::ring_prover` and `into_ring_prover` reduce `key_index` modulo
  the ring capacity. An index at or beyond the capacity panicked in the ring
  proof backend at `prove`.
- A `min_ring_size` of 0 counts as 1 in `RingContext::new`, the `RingSetup`
  constructors and `ring::piop_domain_size`, so every context holds at least
  one key. On Jubjub the PIOP overhead is a power of two, and a ring size of
  0 gave a context with capacity 0: its provers panicked, at `prove` before
  and in `ring_prover` with a division by zero after the reduction above. A
  setup with the SRS of such a domain does not decode any more.
- `RingSetup` deserialization returns `SerializationError::InvalidData` for an
  SRS whose G1 length is not the exact size of a ring domain, `3 * P + 1` for
  a power of two `P`, or with fewer than two G2 powers. Before, an SRS shorter
  than the smallest domain panicked in the domain size arithmetic, and a
  longer one, such as an untrimmed SRS file, decoded as a setup with the largest
  domain it could back, so a node that loaded a raw file that way and a node
  that called `from_pcs_params` built keys on different domains without any
  error.
- Deserialization of `Public`, `Input`, `Output` and of the Thin, Pedersen
  and Ring proofs accepts one encoding per value, on the checked and on the
  unchecked path alike; `Validate::No` skips only the subgroup and identity
  checks. Arkworks decodes the identity from several byte strings and ignores
  the sign flag of an uncompressed Short Weierstrass point, so a Pedersen or
  Ring proof over an empty I/O list, whose `Ok` is the identity, had several
  encodings that all verified. The rule holds on the unchecked path because
  arkworks sequences such as `Vec` decode their elements unchecked and batch
  check the values afterwards, where no encoding rule can run. The decoders
  read one value and stop: framing, and so trailing bytes, is the caller's
  job, as the type docs state.

## [0.5.3] - 2026-08-18

### Changed

- Improved `Error` ergonomics and variants.
- `Secret` hardening: `Debug` redacts the scalar, equality is evaluated in
  constant time, and key derivation zeroizes its temporary seed and scalar
  copies.
- Rename `thin::ThinVrfSuite` to `thin::ThinSuite`.
- Bump `w3f-ring-proof` dependency to 0.0.10.
- `RingSuite` now requires `BaseField: ring_proof::CondSelect`. The ring proof
  backend uses constant-time selection for the secret key bits during witness
  generation.

## [0.5.2] - 2026-08-12

### Added

- `RingContext::new_without_blinding(ring_size)`: runtime replacement for the
  removed `test-vectors` feature. Provers built from such a context generate
  deterministic (non zero-knowledge) proofs, still valid for verifiers using
  a regular context for the same ring size.

### Changed

- arkworks dependencies bumped to 0.6.
- Bump `w3f-ring-proof` dependency to 0.0.9.

### Removed

- `test-vectors` feature. Cargo features are additive: any crate in the
  dependency graph could enable it, silently disabling ring proof blinding
  for every other user of the same build.

### Security

- The group identity is now rejected as a public key: its secret scalar is
  zero and publicly known, so anyone can forge proofs verifying against it.
  `Public::from_affine`, checked deserialization, and the thin and tiny
  verifiers (including batch verification) return `Error::InvalidData` for
  identity keys.
- The group identity is now rejected as a VRF input or output point. The pair
  `(0, 0)` satisfies `O = x * I` for every secret key, so it binds its VRF
  output to no signer. `Input::from_affine`, `Output::from_affine`, checked
  deserialization of both, and all four verifiers (including batch
  verification) return `Error::InvalidData` for such a pair.
- The group identity is now rejected as a Pedersen key commitment. Its opening
  is the public `(0, 0)`, so anyone can build a proof that satisfies the
  commitment equation without a secret.

  The identity remains accepted for the nonce commitments `R` and `Ok`, which
  commit to nothing and are not part of the extraction argument. `Ok` is
  necessarily the identity when no I/O pair is supplied. This matches the
  Bandersnatch VRF specification, section 3.2, 3.3, 4.2 and 4.4 step 1.

## [0.5.1] - 2026-06-12

### Added

- `PcsVerifierParams` type alias for the PCS parameters required by the
  verifier: a few points, independent of ring size, extractable via
  `RingSetup::pcs_verifier_params()` or `VerifierKeyBuilder::pcs_verifier_params()`.
- `ring::verifier_key_from_commitment(commitment, pcs_params)` free function
  to reconstruct a `RingVerifierKey` from a ring commitment without access to
  the full SRS.

## [0.5.0] - 2026-04-27

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

- Bump `w3f-ring-proof` dependency to 0.0.8.
- `RingProofParams` renamed to `RingSetup`.
- `Suite::SUITE_ID` is now a self-describing byte string (e.g.
  `b"Bandersnatch-SHA512-ELL2-v1"`) used directly as the transcript seed and
  hash-to-curve DST prefix, replacing the structured 4-byte
  `SuiteId { version, curve, hash, h2c }`. `Transcript::new` now takes
  `&[u8]`. Breaking change for custom `Suite` implementations.
- Hash-to-curve DST unified to `SUITE_ID || DomSep::HashToCurve` for both
  Try-And-Increment and Elligator2 paths, replacing the prior
  `"ECVRF_" || h2c_suite_id || suite_bytes` form. `hash_to_curve_ell2_xmd`
  and `hash_to_curve_ell2_xof` no longer take a separate `h2c_suite_id`
  argument. `DomSep::HashToCurveTai` is renamed to `HashToCurve` and shared
  across both paths; `ThinBatch`/`PedersenBatch` collapse into a single
  `BatchVerify`.
- `DigestXof` counter widened from `u32` to `u64`.
- Per-suite `BLINDING_BASE`, `ACCUMULATOR_BASE`, `PADDING` points and all
  test vectors regenerated under the new DSTs; previous values do not
  verify.

### Removed

- `RingProofParams::verifier_no_context` method, superseded by
  `RingContext::new`.
- `ring::BatchVerifier::prepare` and `pedersen::BatchVerifier::prepare`,
  superseded by `BatchItem::new` constructors.
- `SuiteId` struct and the `curve`/`hash`/`h2c` constant modules under
  `suites`, superseded by the byte-string `SUITE_ID`.

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

[0.5.3]: https://github.com/davxy/ark-vrf/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/davxy/ark-vrf/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/davxy/ark-vrf/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/davxy/ark-vrf/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/davxy/ark-vrf/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/davxy/ark-vrf/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/davxy/ark-vrf/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/davxy/ark-vrf/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/davxy/ark-vrf/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/davxy/ark-vrf/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/davxy/ark-vrf/releases/tag/v0.1.0
