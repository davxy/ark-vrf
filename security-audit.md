# Security Audit Notes

## 1. Unchecked Subgroup Validation in `ArkworksCodec::point_decode`

**Location:** `src/codec.rs:105`

**Severity:** High

```rust
fn point_decode(buf: &[u8]) -> Result<AffinePoint<S>, Error> {
    AffinePoint::<S>::deserialize_compressed_unchecked(buf).map_err(Into::into)
}
```

`ArkworksCodec::point_decode` uses `deserialize_compressed_unchecked`, which skips
subgroup membership validation. The decoded point is verified to be on the curve
(y is derived from the curve equation during decompression), but it may have a
small-order component for curves with cofactor > 1:

- ed25519: cofactor 8
- bandersnatch: cofactor 4
- jubjub: cofactor 8
- baby-jubjub: cofactor 8

The internal usage in `hash_to_curve_tai_rfc_9381` is safe because it calls
`clear_cofactor()` afterward. However, `point_decode` is also the public
`codec::point_decode::<S>()` API -- the standard way to decode points in the
suite's codec. If used to decode points from untrusted input (e.g., constructing
`Input` or `Output` values from external data), the resulting points could be
outside the prime-order subgroup, enabling small-subgroup attacks against the VRF
schemes.

## 2. Nonce Not Bound to Output in IETF and Pedersen VRF

**Location:** `src/ietf.rs:160`, `src/pedersen.rs:175`

**Severity:** High (requires caller misuse, but the API does not prevent it)

The IETF and Pedersen VRF `prove` functions do not include the `output` parameter
in the nonce derivation:

- IETF: `k = S::nonce(&self.scalar, input, ad.as_ref())`
- Pedersen: `k = S::nonce(&self.scalar, input, &buf)` where `buf` contains the
  blinding factor and `ad`, but not the output.

If the caller invokes `prove` twice with the same `(secret, input, ad)` but
different `output` values, the same nonce `k` is reused with different challenges
`c1`, `c2` (since the output is hashed into the challenge). This enables secret
key recovery:

```
s1 = k + c1 * sk
s2 = k + c2 * sk
sk = (s1 - s2) / (c1 - c2)
```

The Thin VRF (`src/thin.rs:96`) avoids this because its nonce depends on
`merged_input`, which incorporates the output through the `merged_pairs`
delinearization.

The IETF nonce derivation follows RFC-9381 (which assumes the output is always
correctly computed internally). However, this library's API accepts the output as
a caller-provided parameter to support delinearized multi-I/O proofs, creating a
mismatch between the RFC's assumptions and the actual usage surface.
