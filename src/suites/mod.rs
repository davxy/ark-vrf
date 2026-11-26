//! # Built-in cipher suites
//!
//! Each suite has a feature (see the crate docs). The suites follow the format
//! of the RFC 9381 suites. These rules are the same for all of them:
//!
//! - `cLen` = 16 (128-bit security level).
//! - Key pair: `PK = sk * G`, and the secret scalar `x` is `sk`. A seed gives a
//!   secret with [`crate::Secret::from_seed`], with no clamping.
//! - Nonce: deterministic through the suite transcript (see
//!   [`crate::Suite::nonce`]), after RFC 9381 section 5.4.2.2.
//! - `int_to_string` and `string_to_int`: 32 bytes, little-endian. The challenge
//!   `c` is encoded on its low `cLen` bytes.
//! - `point_to_string`, compressed:
//!   - twisted Edwards: `y`, with the top bit of the last byte set when
//!     `x > (p - 1) / 2` (32 bytes);
//!   - short Weierstrass: `x`, then a flag byte, `0x00` when `y <= (p - 1) / 2`
//!     and `0x80` otherwise, or `0x40` for the identity (33 bytes).
//! - `string_to_point` returns "INVALID" if the string does not decode to a
//!   point of `G`.
//!
//! Each suite module gives the rest: `SUITE_ID`, the group, the hash and the
//! hash-to-curve method.

#[cfg(test)]
pub(crate) mod testing;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "secp256r1")]
pub mod secp256r1;

#[cfg(feature = "bandersnatch")]
pub mod bandersnatch;
#[cfg(all(feature = "bandersnatch", feature = "shake128"))]
pub mod bandersnatch_shake128;
#[cfg(feature = "bandersnatch")]
pub mod bandersnatch_sw;
#[cfg(feature = "bandersnatch")]
pub mod bandersnatch_v2;

#[cfg(feature = "jubjub")]
pub mod jubjub;

#[cfg(feature = "baby-jubjub")]
pub mod baby_jubjub;
