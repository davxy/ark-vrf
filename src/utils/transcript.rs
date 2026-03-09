use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::io;
use digest::Digest;
use generic_array::GenericArray;
use sha2::Sha512;

/// Fiat-Shamir transcript with absorb/squeeze interface.
///
/// Provides a streaming hash abstraction where data is absorbed into an
/// internal state and arbitrary-length output is squeezed out.
///
/// Implements [`io::Write`] so that serializable types (points, scalars)
/// can be written directly into the transcript without intermediate buffers.
pub trait Transcript: Clone + io::Read + io::Write {
    /// Create a new transcript with the given domain label.
    fn new(label: &[u8]) -> Self;

    fn fork(&self, label: &[u8]) -> Self {
        let mut t = self.clone();
        t.absorb_raw(label);
        t
    }

    /// Absorb data into the transcript.
    ///
    /// # Panics
    ///
    /// Panics if called after `squeeze_raw`.
    fn absorb_raw(&mut self, data: &[u8]);

    /// Squeeze output bytes from the transcript.
    ///
    /// The first call finalizes the internal hash and transitions to squeezing.
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

/// Hash-based transcript using any `Digest` hasher with counter-mode expansion.
///
/// The squeeze output is produced by hashing the seed with an incrementing
/// counter, generating `H::OutputSize` bytes per block:
///
/// ```text
/// seed = H(label || absorbed_data)
/// block_i = H(seed || i.to_le_bytes())    for i = 0, 1, 2, ...
/// ```
///
/// Blocks are served sequentially, providing an unlimited output stream.
#[derive(Clone)]
pub struct HashTranscript<H: Digest + Clone = Sha512> {
    state: State<H>,
}

#[derive(Clone)]
enum State<H: Digest + Clone> {
    Absorbing(H),
    Squeezing {
        seed: GenericArray<u8, H::OutputSize>,
        counter: u32,
        buffer: GenericArray<u8, H::OutputSize>,
        buf_offset: usize,
    },
}

impl<H: Digest + Clone> io::Read for HashTranscript<H> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.squeeze_raw(buf);
        Ok(buf.len())
    }
}

impl<H: Digest + Clone> io::Write for HashTranscript<H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.absorb_raw(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<H: Digest + Clone> Transcript for HashTranscript<H> {
    fn new(label: &[u8]) -> Self {
        let len = label.len() as u32;
        Self {
            state: State::Absorbing(H::new().chain_update(len.to_le_bytes()).chain_update(label)),
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
            let old = core::mem::replace(&mut self.state, State::Absorbing(H::new()));
            let hasher = match old {
                State::Absorbing(h) => h,
                _ => unreachable!(),
            };
            let seed = hasher.finalize();
            let buffer = H::new()
                .chain_update(&seed)
                .chain_update(0u32.to_le_bytes())
                .finalize();
            self.state = State::Squeezing {
                seed,
                counter: 1,
                buffer,
                buf_offset: 0,
            };
        }

        let State::Squeezing {
            seed,
            counter,
            buffer,
            buf_offset,
        } = &mut self.state
        else {
            unreachable!()
        };

        let mut remaining = buf;
        while !remaining.is_empty() {
            if *buf_offset >= buffer.len() {
                *buffer = H::new()
                    .chain_update(&*seed)
                    .chain_update(counter.to_le_bytes())
                    .finalize();
                *counter += 1;
                *buf_offset = 0;
            }
            let avail = buffer.len() - *buf_offset;
            let take = avail.min(remaining.len());
            remaining[..take].copy_from_slice(&buffer[*buf_offset..*buf_offset + take]);
            *buf_offset += take;
            remaining = &mut remaining[take..];
        }
    }
}

/// BLAKE3-based transcript using the native XOF (extendable output) mode.
///
/// BLAKE3's `finalize_xof()` produces an arbitrary-length output stream
/// directly, so no counter-mode expansion is needed.
#[cfg(feature = "blake3")]
#[derive(Clone)]
pub struct Blake3Transcript {
    state: Blake3State,
}

#[cfg(feature = "blake3")]
#[derive(Clone)]
enum Blake3State {
    Absorbing(blake3::Hasher),
    Squeezing(blake3::OutputReader),
}

#[cfg(feature = "blake3")]
impl io::Read for Blake3Transcript {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.squeeze_raw(buf);
        Ok(buf.len())
    }
}

#[cfg(feature = "blake3")]
impl io::Write for Blake3Transcript {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.absorb_raw(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "blake3")]
impl Transcript for Blake3Transcript {
    fn new(label: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(&(label.len() as u32).to_le_bytes());
        h.update(label);
        Self {
            state: Blake3State::Absorbing(h),
        }
    }

    fn absorb_raw(&mut self, data: &[u8]) {
        match &mut self.state {
            Blake3State::Absorbing(h) => h.update(data),
            Blake3State::Squeezing { .. } => panic!("cannot absorb after squeeze"),
        };
    }

    fn squeeze_raw(&mut self, buf: &mut [u8]) {
        if let Blake3State::Absorbing(_) = &self.state {
            let old = core::mem::replace(
                &mut self.state,
                Blake3State::Absorbing(blake3::Hasher::new()),
            );
            let h = match old {
                Blake3State::Absorbing(h) => h,
                _ => unreachable!(),
            };
            self.state = Blake3State::Squeezing(h.finalize_xof());
        }
        match &mut self.state {
            Blake3State::Squeezing(reader) => reader.fill(buf),
            _ => unreachable!(),
        }
    }
}

/// SHAKE128-based transcript using the native XOF (extendable output) mode.
///
/// SHAKE128's XOF mode produces an arbitrary-length output stream
/// directly, so no counter-mode expansion is needed.
#[cfg(feature = "shake128")]
#[derive(Clone)]
pub struct Shake128Transcript {
    state: Shake128State,
}

#[cfg(feature = "shake128")]
#[derive(Clone)]
enum Shake128State {
    Absorbing(sha3::Shake128),
    Squeezing(sha3::Shake128Reader),
}

#[cfg(feature = "shake128")]
impl io::Read for Shake128Transcript {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.squeeze_raw(buf);
        Ok(buf.len())
    }
}

#[cfg(feature = "shake128")]
impl io::Write for Shake128Transcript {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.absorb_raw(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "shake128")]
impl Transcript for Shake128Transcript {
    fn new(label: &[u8]) -> Self {
        use sha3::digest::Update;
        let h = sha3::Shake128::default()
            .chain(&(label.len() as u32).to_le_bytes())
            .chain(label);
        Self {
            state: Shake128State::Absorbing(h),
        }
    }

    fn absorb_raw(&mut self, data: &[u8]) {
        use sha3::digest::Update;
        match &mut self.state {
            Shake128State::Absorbing(h) => h.update(data),
            Shake128State::Squeezing { .. } => panic!("cannot absorb after squeeze"),
        };
    }

    fn squeeze_raw(&mut self, buf: &mut [u8]) {
        use sha3::digest::{ExtendableOutput, XofReader};
        if let Shake128State::Absorbing(_) = &self.state {
            let old = core::mem::replace(
                &mut self.state,
                Shake128State::Absorbing(sha3::Shake128::default()),
            );
            let h = match old {
                Shake128State::Absorbing(h) => h,
                _ => unreachable!(),
            };
            self.state = Shake128State::Squeezing(h.finalize_xof());
        }
        match &mut self.state {
            Shake128State::Squeezing(reader) => reader.read(buf),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_squeeze() {
        let mut t1 = HashTranscript::<sha2::Sha512>::new(b"test");
        t1.absorb_raw(b"hello");
        let mut out1 = [0u8; 128];
        t1.squeeze_raw(&mut out1);

        let mut t2 = HashTranscript::<sha2::Sha512>::new(b"test");
        t2.absorb_raw(b"hello");
        let mut out2 = [0u8; 128];
        t2.squeeze_raw(&mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn squeeze_incremental_matches_bulk() {
        let mut t1 = HashTranscript::<sha2::Sha512>::new(b"inc");
        t1.absorb_raw(b"data");

        let mut t2 = t1.clone();

        // Squeeze 100 bytes in one go (spans multiple 64-byte blocks).
        let mut bulk = [0u8; 100];
        t1.squeeze_raw(&mut bulk);

        // Squeeze 100 bytes in chunks.
        let mut inc = [0u8; 100];
        t2.squeeze_raw(&mut inc[..10]);
        t2.squeeze_raw(&mut inc[10..64]);
        t2.squeeze_raw(&mut inc[64..]);
        assert_eq!(bulk, inc);
    }

    #[test]
    fn clone_produces_independent_streams() {
        let mut t = HashTranscript::<sha2::Sha512>::new(b"clone");
        t.absorb_raw(b"shared");

        let mut fork = t.clone();
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
        t.absorb_raw(b"y");
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

    #[test]
    fn sha256_works() {
        // SHA-256 produces 32-byte blocks in counter mode.
        let mut t = HashTranscript::<sha2::Sha256>::new(b"test");
        t.absorb_raw(b"hello");
        let mut out = [0u8; 64];
        t.squeeze_raw(&mut out);

        let mut t2 = HashTranscript::<sha2::Sha256>::new(b"test");
        t2.absorb_raw(b"hello");
        let mut out2 = [0u8; 64];
        t2.squeeze_raw(&mut out2);
        assert_eq!(out, out2);
    }

    #[cfg(feature = "shake128")]
    mod shake128_tests {
        use super::super::*;

        #[test]
        fn deterministic_squeeze() {
            let mut t1 = Shake128Transcript::new(b"test");
            t1.absorb_raw(b"hello");
            let mut out1 = [0u8; 64];
            t1.squeeze_raw(&mut out1);

            let mut t2 = Shake128Transcript::new(b"test");
            t2.absorb_raw(b"hello");
            let mut out2 = [0u8; 64];
            t2.squeeze_raw(&mut out2);
            assert_eq!(out1, out2);
        }

        #[test]
        fn incremental_matches_bulk() {
            let mut t1 = Shake128Transcript::new(b"inc");
            t1.absorb_raw(b"data");
            let mut t2 = t1.clone();

            let mut bulk = [0u8; 48];
            t1.squeeze_raw(&mut bulk);

            let mut inc = [0u8; 48];
            t2.squeeze_raw(&mut inc[..10]);
            t2.squeeze_raw(&mut inc[10..32]);
            t2.squeeze_raw(&mut inc[32..]);
            assert_eq!(bulk, inc);
        }

        #[test]
        fn clone_produces_independent_streams() {
            let mut t = Shake128Transcript::new(b"clone");
            t.absorb_raw(b"shared");

            let mut fork = t.clone();
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
            let mut t = Shake128Transcript::new(b"panic");
            t.absorb_raw(b"x");
            let mut out = [0u8; 1];
            t.squeeze_raw(&mut out);
            t.absorb_raw(b"y");
        }

        #[test]
        fn different_labels_produce_different_output() {
            let mut t1 = Shake128Transcript::new(b"label_a");
            let mut t2 = Shake128Transcript::new(b"label_b");
            t1.absorb_raw(b"same");
            t2.absorb_raw(b"same");
            let mut o1 = [0u8; 32];
            let mut o2 = [0u8; 32];
            t1.squeeze_raw(&mut o1);
            t2.squeeze_raw(&mut o2);
            assert_ne!(o1, o2);
        }
    }

    #[cfg(feature = "blake3")]
    mod blake3_tests {
        use super::super::*;

        #[test]
        fn deterministic_squeeze() {
            let mut t1 = Blake3Transcript::new(b"test");
            t1.absorb_raw(b"hello");
            let mut out1 = [0u8; 64];
            t1.squeeze_raw(&mut out1);

            let mut t2 = Blake3Transcript::new(b"test");
            t2.absorb_raw(b"hello");
            let mut out2 = [0u8; 64];
            t2.squeeze_raw(&mut out2);
            assert_eq!(out1, out2);
        }

        #[test]
        fn incremental_matches_bulk() {
            let mut t1 = Blake3Transcript::new(b"inc");
            t1.absorb_raw(b"data");
            let mut t2 = t1.clone();

            let mut bulk = [0u8; 48];
            t1.squeeze_raw(&mut bulk);

            let mut inc = [0u8; 48];
            t2.squeeze_raw(&mut inc[..10]);
            t2.squeeze_raw(&mut inc[10..32]);
            t2.squeeze_raw(&mut inc[32..]);
            assert_eq!(bulk, inc);
        }

        #[test]
        fn clone_produces_independent_streams() {
            let mut t = Blake3Transcript::new(b"clone");
            t.absorb_raw(b"shared");

            let mut fork = t.clone();
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
            let mut t = Blake3Transcript::new(b"panic");
            t.absorb_raw(b"x");
            let mut out = [0u8; 1];
            t.squeeze_raw(&mut out);
            t.absorb_raw(b"y");
        }

        #[test]
        fn different_labels_produce_different_output() {
            let mut t1 = Blake3Transcript::new(b"label_a");
            let mut t2 = Blake3Transcript::new(b"label_b");
            t1.absorb_raw(b"same");
            t2.absorb_raw(b"same");
            let mut o1 = [0u8; 32];
            let mut o2 = [0u8; 32];
            t1.squeeze_raw(&mut o1);
            t2.squeeze_raw(&mut o2);
            assert_ne!(o1, o2);
        }
    }
}
