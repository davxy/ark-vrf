# Elliptic Curve VRF

Verifiable random functions with additional data (VRF-AD) on
[arkworks](https://github.com/arkworks-rs) curves, with `no_std` support. All
schemes use a transcript-based Fiat-Shamir transform and accept several
input/output pairs in one proof.

## Supported Schemes

- **Tiny VRF**: compact proof `(c, s)`, close to
  [RFC 9381](https://datatracker.ietf.org/doc/rfc9381).
- **Thin VRF**: proof `(R, s)`, with batch verification.
- **Pedersen VRF**: the public key is hidden in a Pedersen commitment
  ([BCHSV23](https://eprint.iacr.org/2023/002)).
- **Ring VRF**: Pedersen VRF plus a proof that the committed key is in a ring
  ([CSSV22](https://eprint.iacr.org/2022/1205)).

### Specifications

- [VRF Schemes](https://github.com/davxy/bandersnatch-vrf-spec)
- [Ring Proof](https://github.com/davxy/ring-proof-spec)

## Built-In Suites

Each suite has a feature (see [Features](#features)).

- **Ed25519**: Tiny, Thin and Pedersen VRF.
- **Secp256r1**: Tiny, Thin and Pedersen VRF.
- **Bandersnatch** (_Edwards curve on BLS12-381_): Tiny, Thin, Pedersen and Ring VRF.
  `bandersnatch_v2` uses the RFC 9380 `expand_message_xmd` padding. The
  [specification](https://github.com/davxy/bandersnatch-vrf-spec) recommends version 1.
- **JubJub** (_Edwards curve on BLS12-381_): Tiny, Thin, Pedersen and Ring VRF.
- **Baby-JubJub** (_Edwards curve on BN254_): Tiny, Thin, Pedersen and Ring VRF.

The test vectors of each suite, the Ring VRF setup files and the RFC 9380
vectors are in `data/`; see [`data/README.md`](data/README.md).

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
let io = secret.vrf_io(input);

// Generate a proof that binds the input-output pair and auxiliary data
let proof = TinyProof::prove(io, b"aux data", &secret);
```

_Verify_
```rust,ignore
// Verify the proof against the public key
let result = proof.verify(io, b"aux data", &public);
assert!(result.is_ok());
```

The keys have the same operations as methods: `secret.prove_tiny(io, ad)` and
`public.verify_tiny(io, ad, &proof)`.

### Thin-VRF

VRF-AD with an `(R, s)` proof, which supports batch verification.

_Prove_
```rust,ignore
let io = secret.vrf_io(input);
let proof = ThinProof::prove(io, b"aux data", &secret);
```

_Verify_
```rust,ignore
let result = proof.verify(io, b"aux data", &public);
assert!(result.is_ok());
```

As for Tiny, the keys have the same operations as methods: `secret.prove_thin`
and `public.verify_thin`.

_Batch verify_
```rust,ignore
let proof1 = ThinProof::prove(io, b"data1", &secret);
let proof2 = ThinProof::prove(io, b"data2", &secret);

let mut batch = ThinBatchVerifier::new();
batch.push(io, b"data1", &proof1, &public);
batch.push(io, b"data2", &proof2, &public);
assert!(batch.verify().is_ok());
```

### Pedersen-VRF

The proof holds a Pedersen commitment to the secret key instead of the public key.

_Prove_
```rust,ignore
let io = secret.vrf_io(input);

// Generate a proof with a blinding factor
let (proof, blinding) = PedersenProof::prove(io, b"aux data", &secret);

// The proof includes a commitment to the public key
let key_commitment = proof.key_commitment();
```

_Verify_
```rust,ignore
use ark_ec::CurveGroup;
use ark_vrf::pedersen::PedersenSuite;

// Verify without knowing which specific public key was used.
// Verifies that the secret key used to generate `output` is the same as
// the secret key used to generate `proof.key_commitment()`.
let result = proof.verify(io, b"aux data");
assert!(result.is_ok());

// Verify the proof was created using a specific public key.
// This requires knowledge of the blinding factor.
let expected = (public.into_affine() + blinding.mul_point(BandersnatchSha512Ell2::BLINDING_BASE)).into_affine();
assert_eq!(proof.key_commitment(), expected);
```

The secret key has the same operation as a method: `secret.prove_pedersen`.
Verification needs no public key, so `Public` has no Pedersen method.

### Ring-VRF

The proof shows that the key is in a ring of public keys, but not which key it is.

_Ring construction_
```rust,ignore
const RING_SIZE: usize = 100;
let prover_key_index = 3;

// Construct an example ring with dummy keys
let mut ring = (0..RING_SIZE)
    .map(|i| {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&i.to_le_bytes());
        Secret::from_seed(seed).public()
    })
    .collect::<Vec<_>>();

// Patch the ring with the public key of the prover
ring[prover_key_index] = public;

// Any key can be replaced with the padding point
ring[0] = Public::padding();

// Create parameters for the ring proof system.
// These parameters are reusable across multiple proofs.
// This constructor is for tests only, see "Trusted setup" below.
let ring_setup = RingSetup::from_seed_insecure(RING_SIZE, [0x42; 32]);
```

_Trusted setup_

`from_seed_insecure` and `from_rand_insecure` know the KZG trapdoor, and with it
anybody can forge ring proofs. Use them for tests only, and load the SRS of a
trusted setup ceremony instead. The repository has the Zcash ceremony SRS for the
BLS12-381 suites:

```rust,ignore
use ark_serialize::CanonicalDeserialize;

let srs = std::fs::read("data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin").unwrap();
// Use `deserialize_uncompressed` for a file from an untrusted source.
let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&srs[..]).unwrap();
let ring_setup = RingSetup::from_pcs_params(RING_SIZE, pcs_params).unwrap();
```

_Prove_
```rust,ignore
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
let proof = RingProof::prove(io, b"aux data", &secret, &prover);
```

_Verify_
```rust,ignore
// Create a verifier key for this ring
let verifier_key = ring_setup.verifier_key(&ring).unwrap();

// Create a verifier instance
let ring_ctx = ring_setup.ring_context();
let verifier = ring_ctx.ring_verifier(verifier_key);

// Verify the proof - this confirms that:
// 1. The proof was created by someone who knows a secret key in the ring
// 2. The VRF output is correct for the given input
// But it does NOT reveal which ring member created the proof
let result = proof.verify(io, b"aux data", &verifier);
```

The secret key has the same operation as a method: `secret.prove_ring`.

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

- `default`: `std`. The tests need it.
- `full`: all the curves below, and `ring`.
- `secret-split`: each secret scalar multiplication of Tiny, Thin and Pedersen VRF
  (public key, output, nonce, blinding) uses two random shares of the scalar. This
  protects the scalar value against side channels, at twice the cost. The timing
  stays variable. Ring proof witness generation does not use the split.
  The shares come from `OsRng` at each multiplication, also when a `Secret` is
  decoded, and `OsRng` panics when its backend fails. The feature works with
  `no_std`, but where `getrandom` has no backend, the application must select one:
  `getrandom/js` on `wasm32-unknown-unknown`, `getrandom/custom` or
  `getrandom/rdrand` on bare metal.
- `ring`: Ring VRF for the curves that support it.
- `shake128`: `Shake128Transcript` and the `bandersnatch_shake128` suite.

### Curves

- `ed25519`
- `jubjub`
- `bandersnatch`
- `baby-jubjub`
- `secp256r1`

### Arkworks optimizations

- `parallel`: parallel execution with `rayon`.
- `asm`: assembly for some low level operations.

## License

Distributed under the [MIT License](./LICENSE).
