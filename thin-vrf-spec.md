# Thin VRF Specification

Specification of the Thin VRF scheme as implemented in ark-vrf. The scheme
merges the public-key Schnorr pair `(G, P)` and the VRF I/O pair `(I, O)` into
a single DLEQ relation via delinearization, then proves it with a Schnorr-like
proof `(R, s)`. The `(R, s)` format (storing nonce commitment rather than
challenge) enables batch verification.

This document describes the hash-based variant using RFC-style domain
separation. The original W3F ring-vrf specification uses Merlin-style
transcripts; the translation replaces transcript operations with deterministic
hash constructions.

## Notation

- `F` -- the scalar field of the elliptic curve.
- `G` -- the keying base point (the suite's fixed generator).
- `sk` -- secret key scalar in `F`.
- `P = sk * G` -- public key.
- `H` -- the suite's hash function (e.g. SHA-256, SHA-512).
- `SUITE_ID` -- the suite identifier string.
- `CHALLENGE_LEN` -- number of bytes used for challenge derivation.
- `encode(X)` -- the suite's canonical point encoding of curve point `X`.
- `(I, O)` -- a VRF input/output pair, where `I` is a curve point (from
  hash-to-curve) and `O = sk * I` is the VRF pre-output.

A **ThinVrf proof** consists of a curve point `R` and a scalar `s`.

## Delinearization

Compute 128-bit delinearization weights `(z_0, z_1)` that merge the VRF I/O
pair `(I, O)` and the Schnorr pair `(G, P)` into a single DLEQ relation.

**Input:** public key `P`, VRF input `I`, VRF output `O`.

**Output:** scalars `z_0, z_1` in `F`.

**Steps:**

1. Compute:
   ```
   hash = H(SUITE_ID || 0x11 || encode(G) || encode(P) || encode(I) || encode(O) || 0x00)
   ```

2. Extract two 128-bit scalars:
   ```
   z_0 = from_le_bytes_mod_order(hash[0..16])
   z_1 = from_le_bytes_mod_order(hash[16..32])
   ```

The domain separator `0x11` is distinct from all other domain separators used in
the library (`0x01` = hash-to-curve, `0x02` = IETF challenge, `0x03` =
point-to-hash, `0x12` = Thin VRF challenge, `0xCC` = Pedersen blinding).

The 128-bit width is deliberate: full field-width scalars are not needed for
soundness (the Schwartz-Zippel error probability is already `2^{-128}`), and
the smaller scalars roughly halve the scalar multiplication cost.

**Requires:** hash output length >= 32 bytes.

## Merged pair

Given delinearization weights `(z_0, z_1)`, the merged input and output are:

```
I_m = z_0 * I + z_1 * G
O_m = z_0 * O + z_1 * P
```

If `O = sk * I` and `P = sk * G` (i.e. the same secret key is used in both
relations), then `O_m = sk * I_m`. A cheater using different secrets for the
two relations cannot satisfy this merged equation except with negligible
probability.

## Challenge

Compute the Fiat-Shamir challenge for the Thin VRF proof.

**Input:** public key `P`, VRF input `I`, VRF output `O`, nonce commitment `R`,
additional data `ad`.

**Output:** scalar `c` in `F`.

**Steps:**

1. Compute:
   ```
   hash = H(SUITE_ID || 0x12 || encode(P) || encode(I) || encode(O) || encode(R) || ad || 0x00)
   ```

2. Extract the challenge:
   ```
   c = from_be_bytes_mod_order(hash[0..CHALLENGE_LEN])
   ```

The domain separator `0x12` distinguishes this from the IETF VRF challenge
(`0x02`). The original points `(P, I, O)` are included explicitly rather than
the merged pair, since the merged pair is deterministically derived from them.

## Sign

**Input:** secret key `sk`, public key `P`, VRF input `I`, VRF output `O`,
additional data `ad`.

**Output:** proof `(R, s)`.

**Steps:**

1. Compute delinearization weights:
   ```
   (z_0, z_1) = delinearize(P, I, O)
   ```

2. Compute the merged input:
   ```
   I_m = z_0 * I + z_1 * G
   ```

3. Generate the deterministic nonce:
   ```
   k = nonce(sk, I_m)
   ```
   The nonce function is the suite's standard nonce derivation (e.g. RFC-8032
   section 5.1.6). Using `I_m` as the nonce input commits to all public
   parameters (G, P, I, O) through the delinearization hash.

4. Compute the nonce commitment:
   ```
   R = k * I_m
   ```
   This multiplication uses the secret nonce `k` and must be performed with
   side-channel protections when available (e.g. scalar splitting).

5. Compute the challenge:
   ```
   c = challenge(P, I, O, R, ad)
   ```

6. Compute the response:
   ```
   s = k + c * sk
   ```

7. Return `(R, s)`.

## Verify

**Input:** public key `P`, VRF input `I`, VRF output `O`, additional data `ad`,
proof `(R, s)`.

**Output:** accept or reject.

**Steps:**

1. Compute delinearization weights and merged pair:
   ```
   (z_0, z_1) = delinearize(P, I, O)
   I_m = z_0 * I + z_1 * G
   O_m = z_0 * O + z_1 * P
   ```

2. Recompute the challenge:
   ```
   c = challenge(P, I, O, R, ad)
   ```

3. Check the verification equation:
   ```
   R + c * O_m - s * I_m == 0
   ```
   Accept if the result is the identity point. Reject otherwise.

### Correctness

For an honest signer, `O_m = sk * I_m`, `R = k * I_m`, and `s = k + c * sk`.
Substituting:

```
R + c * O_m - s * I_m
= k * I_m + c * sk * I_m - (k + c * sk) * I_m
= 0
```

Cofactor multiplication is not needed because all points are validated to be in
the prime-order subgroup by the `AffineRepr` deserialization bound, consistent
with the IETF and Pedersen verifiers in this library.

## Batch verification

The `(R, s)` proof format enables batch verification of multiple independent
proofs in a single multi-scalar multiplication.

Given `n` proofs, each with public key `P_i`, VRF pair `(I_i, O_i)`, additional
data `ad_i`, and proof `(R_i, s_i)`:

1. For each proof `i`, compute the merged pair `(I_m_i, O_m_i)` and challenge
   `c_i` (Verify steps 1-2). This per-proof work involves only hashing and
   public scalar multiplications, and can be parallelized.

2. Derive a deterministic RNG by hashing all `(c_i, s_i)` pairs:
   ```
   seed = H(encode(c_0) || encode(s_0) || encode(c_1) || encode(s_1) || ...)[0..32]
   rng = ChaCha20Rng::from_seed(seed)
   ```

3. Sample 128-bit random weights `w_i` from the RNG for each proof.

4. Check the combined equation (a single 3N-point MSM):
   ```
   sum_i  w_i * R_i  +  (w_i * c_i) * O_m_i  -  (w_i * s_i) * I_m_i  ==  0
   ```

If any individual verification equation is non-zero, the weighted sum is
non-zero with probability at least `1 - 2^{-128}` (by Schwartz-Zippel over
the random weights). A passing batch check therefore implies all individual
proofs are valid.

An empty batch (n = 0) is accepted trivially.

## Domain separator summary

| Byte   | Usage                    |
|--------|--------------------------|
| `0x01` | Hash-to-curve (RFC-9381) |
| `0x02` | IETF VRF challenge       |
| `0x03` | Point-to-hash            |
| `0x11` | Thin VRF delinearization |
| `0x12` | Thin VRF challenge       |
| `0xCC` | Pedersen blinding factor  |
