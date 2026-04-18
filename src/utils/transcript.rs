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
///
/// Implementations do **not** need to handle domain separation or
/// length-prefixing of variable-length inputs. The protocol layer
/// takes care of this by absorbing domain-separation tags and explicit
/// lengths before variable-length data. Since `absorb_raw` is a plain
/// concatenation into a single hash stream (absorb then squeeze, no
/// resets), the domain-separation bytes injected by the caller are
/// sufficient to prevent ambiguous parses.
pub trait Transcript: Clone + io::Read + io::Write {
    /// Create a new transcript from the suite identifier.
    fn new(id: &[u8]) -> Self;

    /// Absorb raw bytes into the transcript.
    ///
    /// This is a plain concatenation into the internal hash state.
    /// Domain separation and length-prefixing of variable-length fields
    /// are the caller's responsibility (handled by the protocol layer).
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

    /// Consume the transcript and return an RNG that draws from the squeeze stream.
    fn to_rng(self) -> TranscriptRng<Self>
    where
        Self: Sized,
    {
        TranscriptRng(self)
    }
}

/// RNG wrapper over a [`Transcript`] squeeze stream.
pub struct TranscriptRng<T>(T);

impl<T: Transcript> ark_std::rand::RngCore for TranscriptRng<T> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.squeeze_raw(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.squeeze_raw(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.squeeze_raw(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<T: Transcript> ark_std::rand::CryptoRng for TranscriptRng<T> {}

// ---------------------------------------------------------------------------
// XofTranscript: single transcript implementation for all XOF-like hashers
// ---------------------------------------------------------------------------

/// Transcript backed by any [`ExtendableOutput`](digest::ExtendableOutput) hasher.
///
/// All provided transcript variants are built on this type:
/// - [`HashTranscript`]: fixed-output hashes (SHA-512, SHA-256) via [`DigestXof`]
/// - `Shake128Transcript`: SHAKE128 native XOF (requires `shake128` feature)
pub struct XofTranscript<H: digest::ExtendableOutput + Clone> {
    state: XofState<H>,
}

enum XofState<H: digest::ExtendableOutput + Clone> {
    Absorbing(H),
    Squeezing(H::Reader),
}

impl<H: digest::ExtendableOutput + Default + Clone> Default for XofState<H> {
    fn default() -> Self {
        Self::Absorbing(H::default())
    }
}

impl<H: digest::ExtendableOutput + Clone> Clone for XofTranscript<H>
where
    H::Reader: Clone,
{
    fn clone(&self) -> Self {
        Self {
            state: match &self.state {
                XofState::Absorbing(h) => XofState::Absorbing(h.clone()),
                XofState::Squeezing(r) => XofState::Squeezing(r.clone()),
            },
        }
    }
}

impl<H: digest::ExtendableOutput + Default + Clone> XofTranscript<H> {
    /// Transition to squeezing (if needed) and return the XOF reader.
    fn reader(&mut self) -> &mut H::Reader {
        if let XofState::Absorbing(_) = &self.state {
            let XofState::Absorbing(h) = core::mem::take(&mut self.state) else {
                unreachable!()
            };
            self.state = XofState::Squeezing(h.finalize_xof());
        }
        let XofState::Squeezing(reader) = &mut self.state else {
            unreachable!()
        };
        reader
    }
}

impl<H: digest::ExtendableOutput + Default + Clone> io::Read for XofTranscript<H>
where
    H::Reader: Clone,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.squeeze_raw(buf);
        Ok(buf.len())
    }
}

impl<H: digest::ExtendableOutput + Default + Clone> io::Write for XofTranscript<H>
where
    H::Reader: Clone,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.absorb_raw(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<H: digest::ExtendableOutput + Default + Clone> Transcript for XofTranscript<H>
where
    H::Reader: Clone,
{
    fn new(id: &[u8]) -> Self {
        let mut h = H::default();
        h.update(id);
        Self {
            state: XofState::Absorbing(h),
        }
    }

    fn absorb_raw(&mut self, data: &[u8]) {
        match &mut self.state {
            XofState::Absorbing(h) => h.update(data),
            XofState::Squeezing { .. } => panic!("cannot absorb after squeeze"),
        }
    }

    fn squeeze_raw(&mut self, buf: &mut [u8]) {
        use digest::XofReader;
        self.reader().read(buf);
    }
}

// ---------------------------------------------------------------------------
// DigestXof: counter-mode XOF adapter for fixed-output hashes
// ---------------------------------------------------------------------------

/// Wraps any [`Digest`] hash into an [`ExtendableOutput`](digest::ExtendableOutput)
/// function using counter-mode expansion.
///
/// ```text
/// seed = H(absorbed_data)
/// block_i = H(seed || i.to_le_bytes())    for i = 0, 1, 2, ...
/// ```
#[derive(Clone)]
pub struct DigestXof<H: Digest + Clone>(H);

impl<H: Digest + Clone> Default for DigestXof<H> {
    fn default() -> Self {
        Self(H::new())
    }
}

impl<H: Digest + Clone> digest::Update for DigestXof<H> {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl<H: Digest + Clone> digest::OutputSizeUser for DigestXof<H> {
    type OutputSize = H::OutputSize;
}

impl<H: Digest + Clone> digest::ExtendableOutput for DigestXof<H> {
    type Reader = DigestXofReader<H>;

    fn finalize_xof(self) -> Self::Reader {
        let seed = self.0.finalize();
        let buffer = H::new()
            .chain_update(&seed)
            .chain_update(0u32.to_le_bytes())
            .finalize();
        DigestXofReader {
            seed,
            counter: 1,
            buffer,
            buf_offset: 0,
        }
    }
}

/// Counter-mode XOF reader for [`DigestXof`].
#[derive(Clone)]
pub struct DigestXofReader<H: Digest> {
    seed: GenericArray<u8, H::OutputSize>,
    counter: u64,
    buffer: GenericArray<u8, H::OutputSize>,
    buf_offset: usize,
}

impl<H: Digest> digest::XofReader for DigestXofReader<H> {
    fn read(&mut self, buf: &mut [u8]) {
        let mut remaining = buf;
        while !remaining.is_empty() {
            if self.buf_offset >= self.buffer.len() {
                self.buffer = H::new()
                    .chain_update(&self.seed)
                    .chain_update(self.counter.to_le_bytes())
                    .finalize();
                self.counter += 1;
                self.buf_offset = 0;
            }
            let avail = self.buffer.len() - self.buf_offset;
            let take = avail.min(remaining.len());
            remaining[..take]
                .copy_from_slice(&self.buffer[self.buf_offset..self.buf_offset + take]);
            self.buf_offset += take;
            remaining = &mut remaining[take..];
        }
    }
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Hash-based transcript using counter-mode expansion for fixed-output hashes.
///
/// The squeeze output is produced by hashing a seed with an incrementing
/// counter, generating `H::OutputSize` bytes per block:
///
/// ```text
/// seed = H(label || absorbed_data)
/// block_i = H(seed || i.to_le_bytes())    for i = 0, 1, 2, ...
/// ```
pub type HashTranscript<H = Sha512> = XofTranscript<DigestXof<H>>;

/// SHAKE128 native XOF transcript.
#[cfg(feature = "shake128")]
pub type Shake128Transcript = XofTranscript<sha3::Shake128>;

#[cfg(test)]
mod tests {
    macro_rules! transcript_tests {
        ($T:ty, $mod:ident) => {
            mod $mod {
                use super::super::*;

                const ID_A: &[u8] = b"foo";
                const ID_B: &[u8] = b"bar";

                #[test]
                fn deterministic_squeeze() {
                    let mut t1 = <$T>::new(ID_A);
                    t1.absorb_raw(b"hello");
                    let mut out1 = [0u8; 64];
                    t1.squeeze_raw(&mut out1);

                    let mut t2 = <$T>::new(ID_A);
                    t2.absorb_raw(b"hello");
                    let mut out2 = [0u8; 64];
                    t2.squeeze_raw(&mut out2);
                    assert_eq!(out1, out2);
                }

                #[test]
                fn incremental_matches_bulk() {
                    let mut t1 = <$T>::new(ID_A);
                    t1.absorb_raw(b"data");
                    let mut t2 = t1.clone();

                    let mut bulk = [0u8; 100];
                    t1.squeeze_raw(&mut bulk);

                    let mut inc = [0u8; 100];
                    t2.squeeze_raw(&mut inc[..10]);
                    t2.squeeze_raw(&mut inc[10..64]);
                    t2.squeeze_raw(&mut inc[64..]);
                    assert_eq!(bulk, inc);
                }

                #[test]
                fn clone_produces_independent_streams() {
                    let mut t = <$T>::new(ID_A);
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
                    let mut t = <$T>::new(ID_A);
                    t.absorb_raw(b"x");
                    let mut out = [0u8; 1];
                    t.squeeze_raw(&mut out);
                    t.absorb_raw(b"y");
                }

                #[test]
                fn different_labels_produce_different_output() {
                    let mut t1 = <$T>::new(ID_A);
                    let mut t2 = <$T>::new(ID_B);
                    t1.absorb_raw(b"same");
                    t2.absorb_raw(b"same");
                    let mut o1 = [0u8; 32];
                    let mut o2 = [0u8; 32];
                    t1.squeeze_raw(&mut o1);
                    t2.squeeze_raw(&mut o2);
                    assert_ne!(o1, o2);
                }
            }
        };
    }

    transcript_tests!(HashTranscript<sha2::Sha512>, hash_sha512);
    transcript_tests!(HashTranscript<sha2::Sha256>, hash_sha256);

    #[cfg(feature = "shake128")]
    transcript_tests!(Shake128Transcript, shake128_xof);
}
