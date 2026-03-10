# Elliptic Curve VRF

This library provides flexible and efficient implementations of Verifiable
Random Functions with Additional Data (VRF-AD), a cryptographic construct
that augments a standard VRF scheme by incorporating auxiliary information
into its signature.

It leverages the [Arkworks](https://github.com/arkworks-rs) framework and
supports customization of scheme parameters.

## What is a VRF?

 A Verifiable Random Function (VRF) is a cryptographic primitive that maps inputs
 to verifiable pseudorandom outputs. Key properties include:

 - **Uniqueness**: For a given input and private key, there is exactly one valid output
 - **Verifiability**: Anyone with the public key can verify that an output is correct
 - **Pseudorandomness**: Without the private key, outputs appear random and unpredictable
 - **Collision resistance**: Finding inputs that map to the same output is computationally infeasible

## Supported Schemes

- **IETF VRF**: Based on ECVRF described in [RFC9381](https://datatracker.ietf.org/doc/rfc9381),
  adapted to use a pluggable transcript-based Fiat-Shamir transform and support for
  binding additional data to the proof.

- **Thin VRF**: Merges the Schnorr public-key and VRF I/O DLEQ relations into a single
  delinearized proof. Produces compact proofs (R, s) that support batch verification.

- **Pedersen VRF**: Described in [BCHSV23](https://eprint.iacr.org/2023/002).
  Extends the basic VRF with key-hiding properties using Pedersen commitments.

- **Ring VRF**: A zero-knowledge-based scheme inspired by [BCHSV23](https://eprint.iacr.org/2023/002).
  Provides signer anonymity within a set of public keys (a "ring"), allowing
  verification that a ring member created the proof without revealing which specific member.

### Specifications

- [VRF Schemes](https://github.com/davxy/bandersnatch-vrf-spec)
- [Ring Proof](https://github.com/davxy/ring-proof-spec)

## Built-In Suites

The library conditionally includes the following pre-configured suites (see features section):

- **Ed25519-SHA-512-TAI**: Supports IETF, Thin, and Pedersen VRF.
- **Secp256r1-SHA-256-TAI**: Supports IETF, Thin, and Pedersen VRF.
- **Bandersnatch** (_Edwards curve on BLS12-381_): Supports IETF, Thin, Pedersen, and Ring VRF.
- **JubJub** (_Edwards curve on BLS12-381_): Supports IETF, Thin, Pedersen, and Ring VRF.
- **Baby-JubJub** (_Edwards curve on BN254_): Supports IETF, Thin, Pedersen, and Ring VRF.

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
let hash_bytes = output.hash();
```

### IETF-VRF

The IETF VRF scheme is based on [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
adapted to use a pluggable transcript-based Fiat-Shamir transform.

_Prove_
```rust,ignore
use ark_vrf::ietf::Prover;

let io = secret.vrf_io(input);

// Generate a proof that binds the input-output pair and auxiliary data
let proof = secret.prove(io, b"aux data");
```

_Verify_
```rust,ignore
use ark_vrf::ietf::Verifier;

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

The Pedersen VRF extends the IETF scheme with key-hiding properties using Pedersen commitments.

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
use ark_vrf::pedersen::Verifier;

// Verify without knowing which specific public key was used.
// Verifies that the secret key used to generate `output` is the same as
// the secret key used to generate `proof.key_commitment()`.
let result = Public::verify(io, b"aux data", &proof);
assert!(result.is_ok());

// Verify the proof was created using a specific public key.
// This requires knowledge of the blinding factor.
let expected = (public.0 + BandersnatchSha512Ell2::BLINDING_BASE * blinding).into_affine();
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
        Secret::from_seed(seed).public().0
    })
    .collect::<Vec<_>>();

// Patch the ring with the public key of the prover
ring[prover_key_index] = public.0;

// Any key can be replaced with the padding point
ring[0] = RingProofParams::padding_point();

// Create parameters for the ring proof system.
// These parameters are reusable across multiple proofs.
let params = RingProofParams::from_seed(RING_SIZE, [0x42; 32]);
```

_Prove_
```rust,ignore
use ark_vrf::ring::Prover;

// Create a prover key specific to this ring
let prover_key = params.prover_key(&ring);

// Create a prover instance for the specific position in the ring
let prover = params.prover(prover_key, prover_key_index);

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
let verifier_key = params.verifier_key(&ring);

// Create a verifier instance
let verifier = params.verifier(verifier_key);

// Verify the proof - this confirms that:
// 1. The proof was created by someone who knows a secret key in the ring
// 2. The VRF output is correct for the given input
// But it does NOT reveal which ring member created the proof
let result = Public::verify(io, b"aux data", &proof, &verifier);
```

_Verifier key from commitment_
```rust,ignore
// For efficiency, a commitment to the ring can be shared
let ring_commitment = params.verifier_key(&ring).commitment();

// A verifier can reconstruct the verifier key from just the commitment
// without needing the full ring of public keys
let verifier_key = params.verifier_key_from_commitment(ring_commitment);
```

## Features

- `default`: `std`
- `full`: Enables all features listed below except `secret-split`, `parallel`, `asm`, `test-vectors`.
- `secret-split`: Point scalar multiplication with secret split. Secret scalar is split into the sum
   of two scalars, which randomly mutate but retain the same sum. Incurs 2x penalty in some internal
   sensible scalar multiplications, but provides side channel defenses.
- `ring`: Ring-VRF for the curves supporting it.
- `test-vectors`: Deterministic ring-vrf proof. Useful for reproducible test vectors generation.

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
