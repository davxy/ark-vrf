# Test data

## `vectors/`

Test vectors of the built-in suites. There is one JSON file for each suite and
scheme, `<suite>_<scheme>.json`, where the scheme is `tiny`, `thin`, `pedersen`
or `ring`. The `testing_*` files are for `TestSuite`, the ed25519 suite that the
crate tests use.

Each file holds an array of 7 entries. `comment` is a text label, and the other
values are hex strings:

- `sk`, `pk`: secret scalar and public key.
- `alpha`, `ad`: VRF input data and additional data.
- `h`, `gamma`, `beta`: VRF input point, output point and 32 byte output hash.
- `proof_*`: the proof fields of the scheme.
- `blinding`: the Pedersen blinding factor (Pedersen and Ring).
- `ring_pks`, `ring_pks_com`, `ring_proof`: the 8 public keys of the ring, one
  after the other, the ring commitment and the ring proof (Ring only).

The crate generates these files, so they detect a change of the output. They
are not an independent reference. The `vectors_process` test of each suite
checks its files.

`vectors-generate.sh` regenerates all the files. It runs the ignored
`vectors_generate` tests with the `full` and `shake128` features. Regenerate
only when a change of the output is intentional.

`vectors-print.py <file.json>` prints a vector file as Markdown, in the format
of the test vectors in the [specification](https://github.com/davxy/bandersnatch-vrf-spec).

## `srs/`

Structured reference strings (the KZG parameters of the Ring VRF), as
`PcsParams` in the arkworks uncompressed encoding.

- `bls12-381-srs-2-11-uncompressed-zcash.bin`: derived from the
  [Zcash powers of tau ceremony](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony).
  6145 G1 and 2 G2 powers, a domain of 2^11. This is enough for 1791
  Bandersnatch keys or 1792 Jubjub keys. The ring tests of the BLS12-381 suites
  and the Ring VRF example in the main README use it.
- `bn254-testing-2-9-uncompressed.bin`: generated from the seed `[0u8; 32]`.
  The trapdoor is known, so use it for tests only. 1537 G1 and 2 G2 powers, a
  domain of 2^9. The Baby-JubJub ring tests use it.

## `rfc9380/`

Hash-to-curve vectors of [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380),
copied without change from `poc/vectors/` of
[draft-irtf-cfrg-hash-to-curve](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve).
Only the file names are different: `-` replaces `:`.

- `P256_XMD-SHA-256_SSWU_RO_.json` (Appendix J.1.1): checks `expand_message_xmd`
  with SHA-256.
- `edwards25519_XMD-SHA-512_ELL2_RO_.json` (Appendix J.5.1): checks
  `expand_message_xmd` with SHA-512 and the arkworks Elligator2 map.

The tests are in `src/utils/hash_to_curve.rs`.
