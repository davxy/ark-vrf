use ark_std::rand::{RngCore, SeedableRng};

use crate::codec::Codec;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::io;
use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use rand_chacha::ChaCha20Rng;

/// Fiat-Shamir transcript with absorb/squeeze interface.
///
/// Provides a streaming hash abstraction where data is absorbed into an
/// internal state and arbitrary-length output is squeezed out using an
/// RNG extension.
///
/// Implements [`io::Write`] so that serializable types (points, scalars)
/// can be written directly into the transcript without intermediate buffers.
pub trait Transcript: Clone + io::Read + io::Write {
    /// Hash output size (before RNG extension).
    type OutputSize: ArrayLength<u8>;

    /// Create a new transcript with the given domain label.
    fn new(label: &[u8]) -> Self;

    /// Absorb data into the transcript.
    ///
    /// # Panics
    ///
    /// Panics if called after `squeeze_raw`.
    fn absorb_raw(&mut self, data: &[u8]);

    /// Squeeze output bytes from the transcript.
    ///
    /// The first call finalizes the internal hash. Direct hash bytes
    /// (if any) are returned first, then the RNG provides unlimited
    /// additional output.
    ///
    /// After the first `squeeze_raw` call, `absorb_raw` must not be called.
    fn squeeze_raw(&mut self, buf: &mut [u8]);

    /// Absorb a serializable object into the transcript.
    ///
    /// Serializes the object directly into the transcript via the
    /// [`io::Write`] implementation, avoiding intermediate allocations.
    fn absorb_serialize(&mut self, obj: &impl CanonicalSerialize) {
        obj.serialize_compressed(self).unwrap();
    }

    /// Squeeze and deserialize an object from the transcript.
    ///
    /// Reads bytes from the squeeze_raw stream via the [`io::Read`]
    /// implementation and deserializes them directly.
    fn squeeze_deserialize<T: CanonicalDeserialize>(&mut self) -> T {
        T::deserialize_compressed(self).unwrap()
    }
}

/// Hash-based transcript using any `Digest` hasher and a seedable RNG extension.
///
/// The squeeze output is structured as:
///
/// ```text
/// Hash output (H bytes), RNG seed (S bytes):
///   [ H-S bytes returned directly | S bytes = RNG seed ]
///
/// Squeeze stream:
///   hash[0..H-S]  then  RNG(seed = hash[H-S..H])
/// ```
///
/// With ChaCha20Rng (S=32) and SHA-512 (H=64): 32 direct bytes, then ChaCha20.
/// With ChaCha20Rng (S=32) and SHA-256 (H=32): pure ChaCha20 (0 direct bytes).
#[derive(Clone)]
pub struct HashTranscript<H: Digest + Clone, R: SeedableRng + RngCore + Clone = ChaCha20Rng> {
    state: State<H, R>,
}

#[derive(Clone)]
enum State<H: Digest + Clone, R: SeedableRng + RngCore + Clone> {
    Absorbing(H),
    Squeezing {
        direct: GenericArray<u8, H::OutputSize>,
        direct_len: usize,
        direct_offset: usize,
        rng: R,
    },
}

impl<H: Digest + Clone, R: SeedableRng + RngCore + Clone> io::Read for HashTranscript<H, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.squeeze_raw(buf);
        Ok(buf.len())
    }
}

impl<H: Digest + Clone, R: SeedableRng + RngCore + Clone> io::Write for HashTranscript<H, R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.absorb_raw(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<H: Digest + Clone, R: SeedableRng + RngCore + Clone> Transcript for HashTranscript<H, R> {
    type OutputSize = H::OutputSize;

    fn new(label: &[u8]) -> Self {
        Self {
            state: State::Absorbing(H::new().chain_update(label)),
        }
    }

    fn absorb_raw(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Absorbing(hasher) => hasher.update(data),
            State::Squeezing { .. } => panic!("cannot absorb after squeeze"),
        }
    }

    fn squeeze_raw(&mut self, buf: &mut [u8]) {
        // Transition from absorbing to squeezing on first call.
        if let State::Absorbing(_) = &self.state {
            // Take ownership via replace with a dummy.
            let old = core::mem::replace(
                &mut self.state,
                State::Absorbing(H::new()), // temporary
            );
            let hasher = match old {
                State::Absorbing(h) => h,
                _ => unreachable!(),
            };
            let hash = hasher.finalize();
            let h_len = hash.len();
            let mut seed = R::Seed::default();
            let seed_bytes = seed.as_mut();
            let seed_len = seed_bytes.len();
            assert!(
                h_len >= seed_len,
                "hash output ({h_len} bytes) is smaller than RNG seed ({seed_len} bytes)"
            );
            let direct_len = h_len - seed_len;
            seed_bytes.copy_from_slice(&hash[direct_len..direct_len + seed_len]);
            self.state = State::Squeezing {
                direct: hash,
                direct_len,
                direct_offset: 0,
                rng: R::from_seed(seed),
            };
        }

        let State::Squeezing {
            direct,
            direct_len,
            direct_offset,
            rng,
        } = &mut self.state
        else {
            unreachable!()
        };

        let mut remaining = buf;

        // Serve from direct bytes first.
        if *direct_offset < *direct_len {
            let avail = *direct_len - *direct_offset;
            let take = avail.min(remaining.len());
            remaining[..take].copy_from_slice(&direct[*direct_offset..*direct_offset + take]);
            *direct_offset += take;
            remaining = &mut remaining[take..];
        }

        // The rest comes from the RNG.
        if !remaining.is_empty() {
            rng.fill_bytes(remaining);
        }
    }
}

/// Squeeze bytes from a transcript and decode them as a scalar field element.
pub fn squeeze_scalar<S: crate::Suite>(
    transcript: &mut impl Transcript,
    len: usize,
) -> crate::ScalarField<S> {
    let mut buf = ark_std::vec![0u8; len];
    transcript.squeeze_raw(&mut buf);
    S::Codec::scalar_decode(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_squeeze_direct_then_chacha() {
        let mut t = HashTranscript::<sha2::Sha512>::new(b"test");
        t.absorb_raw(b"hello");

        // SHA-512 produces 64 bytes: 32 direct + 32 seed.
        let mut out = [0u8; 64];
        t.squeeze_raw(&mut out);

        // First 32 bytes should be the direct hash bytes.
        // Remaining 32 bytes should be ChaCha20 output.
        // Just verify determinism: squeeze the same transcript twice.
        let mut t2 = HashTranscript::<sha2::Sha512>::new(b"test");
        t2.absorb_raw(b"hello");
        let mut out2 = [0u8; 64];
        t2.squeeze_raw(&mut out2);
        assert_eq!(out, out2);
    }

    #[test]
    fn sha256_squeeze_pure_chacha() {
        let mut t = HashTranscript::<sha2::Sha256>::new(b"test");
        t.absorb_raw(b"hello");

        // SHA-256 produces 32 bytes: 0 direct + 32 seed.
        // Everything comes from ChaCha20.
        let mut out = [0u8; 64];
        t.squeeze_raw(&mut out);

        let mut t2 = HashTranscript::<sha2::Sha256>::new(b"test");
        t2.absorb_raw(b"hello");
        let mut out2 = [0u8; 64];
        t2.squeeze_raw(&mut out2);
        assert_eq!(out, out2);
    }

    #[test]
    fn squeeze_incremental_matches_bulk() {
        let mut t1 = HashTranscript::<sha2::Sha512>::new(b"inc");
        t1.absorb_raw(b"data");

        let mut t2 = t1.clone();

        // Squeeze 48 bytes in one go.
        let mut bulk = [0u8; 48];
        t1.squeeze_raw(&mut bulk);

        // Squeeze 48 bytes in chunks.
        let mut inc = [0u8; 48];
        t2.squeeze_raw(&mut inc[..10]);
        t2.squeeze_raw(&mut inc[10..32]);
        t2.squeeze_raw(&mut inc[32..]);
        assert_eq!(bulk, inc);
    }

    #[test]
    fn clone_produces_independent_streams() {
        let mut t = HashTranscript::<sha2::Sha512>::new(b"clone");
        t.absorb_raw(b"shared");

        let mut fork = t.clone();
        // Absorb different data on each fork.
        t.absorb_raw(b"branch_a");
        fork.absorb_raw(b"branch_b");

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        t.squeeze_raw(&mut a);
        fork.squeeze_raw(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    #[should_panic(expected = "cannot absorb after squeeze")]
    fn absorb_after_squeeze_panics() {
        let mut t = HashTranscript::<sha2::Sha256>::new(b"panic");
        t.absorb_raw(b"x");
        let mut out = [0u8; 1];
        t.squeeze_raw(&mut out);
        t.absorb_raw(b"y"); // should panic
    }

    #[test]
    fn different_labels_produce_different_output() {
        let mut t1 = HashTranscript::<sha2::Sha256>::new(b"label_a");
        let mut t2 = HashTranscript::<sha2::Sha256>::new(b"label_b");
        t1.absorb_raw(b"same");
        t2.absorb_raw(b"same");
        let mut o1 = [0u8; 32];
        let mut o2 = [0u8; 32];
        t1.squeeze_raw(&mut o1);
        t2.squeeze_raw(&mut o2);
        assert_ne!(o1, o2);
    }
}
