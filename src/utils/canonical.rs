//! Canonical decoding: one accepted byte string per value.
//!
//! Arkworks reads the identity from several byte strings and ignores the sign
//! flag of an uncompressed Short Weierstrass point. The decoder here compares
//! the consumed bytes with a fresh encoding of the value.

use super::common::STACK_BUF_SIZE;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Recorded bytes: a stack array while they fit, a heap vector after that.
enum Recorded {
    Stack([u8; STACK_BUF_SIZE], usize),
    Heap(Vec<u8>),
}

/// Reader that keeps a copy of every byte it hands out.
struct Recorder<R> {
    inner: R,
    bytes: Recorded,
}

impl<R> Recorder<R> {
    fn record(&mut self, chunk: &[u8]) {
        match &mut self.bytes {
            Recorded::Stack(stack, len) if *len + chunk.len() <= STACK_BUF_SIZE => {
                stack[*len..*len + chunk.len()].copy_from_slice(chunk);
                *len += chunk.len();
            }
            Recorded::Stack(stack, len) => {
                let mut heap = stack[..*len].to_vec();
                heap.extend_from_slice(chunk);
                self.bytes = Recorded::Heap(heap);
            }
            Recorded::Heap(heap) => heap.extend_from_slice(chunk),
        }
    }

    fn recorded(&self) -> &[u8] {
        match &self.bytes {
            Recorded::Stack(stack, len) => &stack[..*len],
            Recorded::Heap(heap) => heap,
        }
    }
}

impl<R: ark_std::io::Read> ark_std::io::Read for Recorder<R> {
    fn read(&mut self, buf: &mut [u8]) -> ark_std::io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.record(&buf[..count]);
        Ok(count)
    }
}

/// Writer that compares the bytes it receives with an expected string.
struct Matcher<'a> {
    expected: &'a [u8],
    mismatch: bool,
}

impl ark_std::io::Write for Matcher<'_> {
    fn write(&mut self, buf: &[u8]) -> ark_std::io::Result<usize> {
        match self.expected.split_at_checked(buf.len()) {
            Some((head, tail)) if head == buf => self.expected = tail,
            _ => self.mismatch = true,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> ark_std::io::Result<()> {
        Ok(())
    }
}

/// Decode a value and accept only the bytes that the value itself encodes to.
///
/// The comparison covers the consumed bytes, so it runs per component inside
/// a stream decoder; [`CanonicalDeserializeExact`] covers the end of the
/// string. It runs on both paths, because arkworks sequences decode their
/// elements with `Validate::No` and batch check them afterwards. `validate`
/// gates a `Valid::check` of the value, because the arkworks BLS12-381
/// decoder skips the on-curve test of an uncompressed point. The consumed
/// bytes are kept in a stack buffer that holds a point of every built-in
/// suite, and spill to the heap past it.
///
/// Implemented for every type that serializes and deserializes.
pub(crate) trait CanonicalDeserializeStrict:
    ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize
{
    fn deserialize_strict(
        reader: impl ark_std::io::Read,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut recorder = Recorder {
            inner: reader,
            bytes: Recorded::Stack([0u8; STACK_BUF_SIZE], 0),
        };
        let value =
            Self::deserialize_with_mode(&mut recorder, compress, ark_serialize::Validate::No)?;
        let mut matcher = Matcher {
            expected: recorder.recorded(),
            mismatch: false,
        };
        value.serialize_with_mode(&mut matcher, compress)?;
        if matcher.mismatch || !matcher.expected.is_empty() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        if matches!(validate, ark_serialize::Validate::Yes) {
            ark_serialize::Valid::check(&value)?;
        }
        Ok(value)
    }
}

impl<T: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize>
    CanonicalDeserializeStrict for T
{
}

/// Decode a value from a byte string that holds nothing else.
///
/// The arkworks decoders stop after the value and leave trailing bytes
/// unread, so every value has an encoding of every longer length, and a
/// deduplication on the bytes of a proof or of a key sees one value many
/// times. These decoders reject a byte string with a byte past the value.
///
/// Each method is the [`CanonicalDeserialize`](ark_serialize::CanonicalDeserialize)
/// method of the same name, on a byte string instead of a reader.
/// Implemented for every type of that trait.
pub trait CanonicalDeserializeExact: ark_serialize::CanonicalDeserialize {
    /// [`deserialize_with_mode`](ark_serialize::CanonicalDeserialize::deserialize_with_mode)
    /// on `bytes`, and an error if a byte is left over.
    fn deserialize_with_mode_exact(
        bytes: &[u8],
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut reader = bytes;
        let value = Self::deserialize_with_mode(&mut reader, compress, validate)?;
        if !reader.is_empty() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(value)
    }

    /// Compressed form, with validation.
    fn deserialize_compressed_exact(
        bytes: &[u8],
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_with_mode_exact(
            bytes,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes,
        )
    }

    /// Compressed form, without validation.
    fn deserialize_compressed_unchecked_exact(
        bytes: &[u8],
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_with_mode_exact(
            bytes,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::No,
        )
    }

    /// Uncompressed form, with validation.
    fn deserialize_uncompressed_exact(
        bytes: &[u8],
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_with_mode_exact(
            bytes,
            ark_serialize::Compress::No,
            ark_serialize::Validate::Yes,
        )
    }

    /// Uncompressed form, without validation.
    fn deserialize_uncompressed_unchecked_exact(
        bytes: &[u8],
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_with_mode_exact(
            bytes,
            ark_serialize::Compress::No,
            ark_serialize::Validate::No,
        )
    }
}

impl<T: ark_serialize::CanonicalDeserialize> CanonicalDeserializeExact for T {}

#[cfg(test)]
mod tests {
    use crate::suites::testing::TestSuite;
    use crate::testing::{TEST_SEED, random_val};
    use crate::*;
    use ark_serialize::{Compress, SerializationError, Validate};

    /// Arkworks stops after the value and leaves the rest of the string
    /// unread, so a proof with a byte appended still decodes, and a
    /// deduplication on proof bytes sees two proofs. Every exact decoder
    /// accepts the value alone; each convenience is checked on its own, as
    /// a wrong mode in one of them would go unnoticed otherwise.
    #[test]
    fn exact_decode_rejects_trailing_bytes() {
        type Proof = crate::thin::Proof<TestSuite>;
        type Decode = fn(&[u8]) -> Result<Proof, SerializationError>;

        let secret = Secret::<TestSuite>::from_seed(TEST_SEED);
        let io = secret.vrf_io(Input::from_affine_unchecked(random_val(None)));
        let proof = secret.prove_thin(io, b"ad");
        let mut compressed = Vec::new();
        proof.serialize_compressed(&mut compressed).unwrap();
        let mut uncompressed = Vec::new();
        proof.serialize_uncompressed(&mut uncompressed).unwrap();
        assert_ne!(compressed.len(), uncompressed.len());

        let mut longer = compressed.clone();
        longer.push(0);
        assert!(Proof::deserialize_compressed(&longer[..]).is_ok());
        assert!(Proof::deserialize_with_mode_exact(&longer, Compress::Yes, Validate::Yes).is_err());

        let exact = Proof::deserialize_compressed_exact(&compressed).unwrap();
        assert!(secret.public().verify_thin(io, b"ad", &exact).is_ok());

        let decoders: [(&[u8], Decode); 4] = [
            (&compressed, Proof::deserialize_compressed_exact),
            (&compressed, Proof::deserialize_compressed_unchecked_exact),
            (&uncompressed, Proof::deserialize_uncompressed_exact),
            (
                &uncompressed,
                Proof::deserialize_uncompressed_unchecked_exact,
            ),
        ];
        for (bytes, decode) in decoders {
            assert!(decode(bytes).is_ok());
            assert!(decode(&bytes[..bytes.len() - 1]).is_err());
            assert!(decode(&[bytes, &[0][..]].concat()).is_err());
        }
    }
}
