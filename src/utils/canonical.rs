//! Canonical decoding: one accepted byte string per value.
//!
//! Arkworks reads the identity from several byte strings and ignores the sign
//! flag of an uncompressed Short Weierstrass point, so one point can have more
//! than one accepted encoding. The decoders here record the consumed bytes and
//! stream a fresh encoding of the decoded value against them, which leaves
//! exactly one, on the checked and on the unchecked path alike.

use super::common::STACK_BUF_SIZE;
use crate::*;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Recorded bytes: a stack array while they fit, a heap vector after that.
enum Recorded<const N: usize> {
    Stack([u8; N], usize),
    Heap(Vec<u8>),
}

/// Reader that keeps a copy of every byte it hands out.
struct Recorder<R, const N: usize> {
    inner: R,
    bytes: Recorded<N>,
}

impl<R, const N: usize> Recorder<R, N> {
    fn record(&mut self, chunk: &[u8]) {
        match &mut self.bytes {
            Recorded::Stack(stack, len) if *len + chunk.len() <= N => {
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

impl<R: ark_std::io::Read, const N: usize> ark_std::io::Read for Recorder<R, N> {
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
/// `validate` goes to the inner decoder for its subgroup check and does not
/// gate the comparison: arkworks sequences decode their elements with
/// `Validate::No` and batch check the values afterwards, so a rule gated on it
/// would never reach a value inside a `Vec`. The consumed bytes sit in an `N`
/// byte stack buffer and spill to the heap if the value is larger.
pub(crate) fn deserialize_canonical<T, const N: usize>(
    reader: impl ark_std::io::Read,
    compress: ark_serialize::Compress,
    validate: ark_serialize::Validate,
) -> Result<T, ark_serialize::SerializationError>
where
    T: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize,
{
    let mut recorder = Recorder {
        inner: reader,
        bytes: Recorded::Stack([0u8; N], 0),
    };
    let value = T::deserialize_with_mode(&mut recorder, compress, validate)?;
    let mut matcher = Matcher {
        expected: recorder.recorded(),
        mismatch: false,
    };
    value.serialize_with_mode(&mut matcher, compress)?;
    if matcher.mismatch || !matcher.expected.is_empty() {
        return Err(ark_serialize::SerializationError::InvalidData);
    }
    Ok(value)
}

/// [`deserialize_canonical`] for one affine point with the default stack
/// buffer: a point encodes to at most 65 bytes on every built-in suite.
pub(crate) fn deserialize_point<S: Suite>(
    reader: impl ark_std::io::Read,
    compress: ark_serialize::Compress,
    validate: ark_serialize::Validate,
) -> Result<AffinePoint<S>, ark_serialize::SerializationError> {
    deserialize_canonical::<AffinePoint<S>, STACK_BUF_SIZE>(reader, compress, validate)
}
