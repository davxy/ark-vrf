# Elliptic Curve VRF

Implementations of Verifiable Random Function with Additional Data (VRF-AD)
schemes built on a transcript-based Fiat-Shamir transform with support for
multiple input/output pairs via delinearization.

Built on the [Arkworks](https://github.com/arkworks-rs) framework with
configurable cryptographic parameters and `no_std` support.

## Supported Schemes

- **Tiny VRF**: Compact proof. Loosely inspired by [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
  adapted with a transcript-based Fiat-Shamir transform, support for additional
  data, and multiple I/O pairs via delinearization.

- **Thin VRF**: Same structure as Tiny VRF but stores the nonce commitment instead
  of the challenge, enabling batch verification at the cost of a slightly larger proof.

- **Pedersen VRF**: Key-hiding VRF based on the construction introduced by
  [BCHSV23](https://eprint.iacr.org/2023/002). Replaces the public key with a
  Pedersen commitment to the secret key, serving as a building block for anonymized
  ring signatures.

- **Ring VRF**: Anonymized ring VRF combining Pedersen VRF with the ring proof scheme
  derived from [CSSV22](https://eprint.iacr.org/2022/1205). Proves that a single
  blinded key is a member of a committed ring without revealing which one.

### Specifications

- [VRF Schemes](https://github.com/davxy/bandersnatch-vrf-spec)
- [Ring Proof](https://github.com/davxy/ring-proof-spec)

## Built-In Suites

The library conditionally includes the following pre-configured suites (see features section):

- **Ed25519**: Supports Tiny, Thin, and Pedersen VRF.
- **Secp256r1**: Supports Tiny, Thin, and Pedersen VRF.
- **Bandersnatch** (_Edwards curve on BLS12-381_): Supports Tiny, Thin, Pedersen, and Ring VRF.
- **JubJub** (_Edwards curve on BLS12-381_): Supports Tiny, Thin, Pedersen, and Ring VRF.
- **Baby-JubJub** (_Edwards curve on BN254_): Supports Tiny, Thin, Pedersen, and Ring VRF.

## Basic Usage

```rust,ignore
use ark_vrf::suites::bandersnatch::*;

// Create a secret key from a seed
let secret = Secret::from_seed([0; 32]);

// Derive the corresponding public key
let public = secret.public();

// Create an input by hashing data to a curve point
let input = Input::new(b"example input").unwrap();

// Compute the VRF output (gamma point)
let output = secret.output(input);

// Get a deterministic hash from the VRF output point
let hash_bytes: [u8; 32] = output.hash();
```

### Tiny VRF

Compact VRF-AD producing a short `(c, s)` proof.

_Prove_
```rust,ignore
use ark_vrf::tiny::Prover;

let io = secret.vrf_io(input);

// Generate a proof that binds the input-output pair and auxiliary data
let proof = secret.prove(io, b"aux data");
```

_Verify_
```rust,ignore
use ark_vrf::tiny::Verifier;

// Verify the proof against the public key
let result = public.verify(io, b"aux data", &proof);
assert!(result.is_ok());
```

### Thin-VRF

The Thin VRF merges the public-key Schnorr pair and the VRF I/O pair into a
single DLEQ relation via delinearization, then proves it with a Schnorr-like
proof (R, s).

_Prove_
```rust,ignore
use ark_vrf::thin::Prover;

let io = secret.vrf_io(input);
let proof = secret.prove(io, b"aux data");
```

_Verify_
```rust,ignore
use ark_vrf::thin::Verifier;

let result = public.verify(io, b"aux data", &proof);
assert!(result.is_ok());
```

_Batch verify_
```rust,ignore
use ark_vrf::thin::{Prover, BatchVerifier};

let proof1 = secret.prove(io, b"data1");
let proof2 = secret.prove(io, b"data2");

let mut batch = BatchVerifier::new();
batch.push(&public, io, b"data1", &proof1);
batch.push(&public, io, b"data2", &proof2);
assert!(batch.verify().is_ok());
```

### Pedersen-VRF

Key-hiding VRF that replaces the public key with a Pedersen commitment to the secret key.

_Prove_
```rust,ignore
use ark_vrf::pedersen::Prover;

let io = secret.vrf_io(input);

// Generate a proof with a blinding factor
let (proof, blinding) = secret.prove(io, b"aux data");

// The proof includes a commitment to the public key
let key_commitment = proof.key_commitment();
```

_Verify_
```rust,ignore
use ark_ec::CurveGroup;
use ark_vrf::pedersen::{PedersenSuite, Verifier};

// Verify without knowing which specific public key was used.
// Verifies that the secret key used to generate `output` is the same as
// the secret key used to generate `proof.key_commitment()`.
let result = Public::verify(io, b"aux data", &proof);
assert!(result.is_ok());

// Verify the proof was created using a specific public key.
// This requires knowledge of the blinding factor.
let expected = (public.point() + BandersnatchSha512Ell2::BLINDING_BASE * blinding).into_affine();
assert_eq!(proof.key_commitment(), expected);
```

### Ring-VRF

The Ring VRF provides anonymity within a set of public keys using zero-knowledge proofs.

_Ring construction_
```rust,ignore
const RING_SIZE: usize = 100;
let prover_key_index = 3;

// Construct an example ring with dummy keys
let mut ring = (0..RING_SIZE)
    .map(|i| {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&i.to_le_bytes());
        Secret::from_seed(seed).public().point()
    })
    .collect::<Vec<_>>();

// Patch the ring with the public key of the prover
ring[prover_key_index] = public.point();

// Any key can be replaced with the padding point
ring[0] = RingSetup::padding_point();

// Create parameters for the ring proof system.
// These parameters are reusable across multiple proofs.
// This constructor is for tests only, see "Trusted setup" below.
let ring_setup = RingSetup::from_seed_insecure(RING_SIZE, [0x42; 32]);
```

_Trusted setup_

`from_seed_insecure` and `from_rand_insecure` generate the KZG trapdoor locally,
so whoever generated it can forge ring proofs. A deployment loads the SRS of a
trusted setup ceremony instead. The repository ships the Zcash ceremony SRS for
the BLS12-381 suites:

```rust,ignore
use ark_serialize::CanonicalDeserialize;

let srs = std::fs::read("data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin").unwrap();
// Use `deserialize_uncompressed` for a file from an untrusted source.
let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&srs[..]).unwrap();
let ring_setup = RingSetup::from_pcs_params(RING_SIZE, pcs_params).unwrap();
```

_Prove_
```rust,ignore
use ark_vrf::ring::Prover;

// Create a prover key specific to this ring
let prover_key = ring_setup.prover_key(&ring).unwrap();

// Create a lightweight ring context for prover/verifier construction
let ring_ctx = ring_setup.ring_context();

// Create a prover instance for the specific position in the ring
let prover = ring_ctx.ring_prover(prover_key, prover_key_index);

let io = secret.vrf_io(input);

// Generate a zero-knowledge proof that:
// 1. The prover knows a secret key for one of the public keys in the ring
// 2. That secret key was used to generate the VRF output
let proof = secret.prove(io, b"aux data", &prover);
```

_Verify_
```rust,ignore
use ark_vrf::ring::Verifier;

// Create a verifier key for this ring
let verifier_key = ring_setup.verifier_key(&ring).unwrap();

// Create a verifier instance
let ring_ctx = ring_setup.ring_context();
let verifier = ring_ctx.ring_verifier(verifier_key);

// Verify the proof - this confirms that:
// 1. The proof was created by someone who knows a secret key in the ring
// 2. The VRF output is correct for the given input
// But it does NOT reveal which ring member created the proof
let result = Public::verify(io, b"aux data", &proof, &verifier);
```

_Both keys_
```rust,ignore
// A party that needs both keys indexes the ring once. The two calls above
// each build both keys and drop one half, so they cost twice as much.
let (prover_key, verifier_key) = ring_setup.keys(&ring).unwrap();
```

_Verifier key from commitment_
```rust,ignore
// For efficiency, a commitment to the ring can be shared
let ring_commitment = ring_setup.verifier_key(&ring).unwrap().commitment();

// A verifier can reconstruct the verifier key from just the commitment
// without needing the full ring of public keys
let verifier_key = ring_setup.verifier_key_from_commitment(ring_commitment);
```

## Features

- `default`: `std`. The test suite needs it: `cargo test --no-default-features`
  stops with one error that says so. The `no_std` build is checked with
  `cargo check --no-default-features --features full`, and with `secret-split`
  by the application crate in `.github/no-std-check` on `x86_64-unknown-none`.
- `full`: All the curves below plus `ring`.
- `secret-split`: Split-secret scalar multiplication. Secret scalar is split into the sum
   of two scalars, which randomly mutate but retain the same sum. Incurs 2x penalty in the
   secret scalar multiplications of the Tiny, Thin and Pedersen VRFs (public key
   derivation, output, nonce and blinding), but provides side channel defenses for them.
   The split draws from `OsRng` on every secret scalar multiplication, `Secret`
   deserialization included. The feature is `no_std`. It enables
   `rand/getrandom`, so the application must give `getrandom` a backend where
   it has none: `getrandom/js` on `wasm32-unknown-unknown`, `getrandom/custom`
   or `getrandom/rdrand` on bare metal. `OsRng` panics where the backend fails
   at run time.
   The multiplication stays variable time with the feature and without it.
   Ring proof witness generation is not covered by this feature: it relies on the
   branch-free handling of the secret bits
   implemented in the `w3f-ring-proof` and `w3f-plonk-common` crates.
- `ring`: Ring-VRF for the curves supporting it.
- `shake128`: `Shake128Transcript` and the `bandersnatch_shake128` suite.
- `print-trace`: Forwards to `ark-std/print-trace`. The ring proof backend prints
  the timers of its phases.

### Curves

- `ed25519`
- `jubjub`
- `bandersnatch`
- `baby-jubjub`
- `secp256r1`

### Arkworks optimizations

- `parallel`: Parallel execution where worth using `rayon`.
- `asm`: Assembly implementation of some low level operations.

## License

Distributed under the [MIT License](./LICENSE).
