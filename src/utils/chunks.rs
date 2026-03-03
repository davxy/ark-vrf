use ark_std::borrow::Cow;
use ark_std::vec::Vec;

/// A sequence of byte slices that can be fed into a hasher without allocation.
///
/// Implemented for `&[u8]`, `Vec<u8>`, and fixed-size arrays of byte slices
/// (`[&[u8]; N]`), allowing functions to accept both plain byte slices and
/// multi-slice inputs through a single generic parameter.
pub trait ByteChunks {
    /// Feed all chunks into a [`digest::Digest`] hasher.
    fn feed_to<H: digest::Digest>(&self, hasher: &mut H);

    /// Return the bytes as a contiguous slice.
    ///
    /// For single-slice types this returns a borrowed reference with no allocation.
    /// For multi-slice types this concatenates the chunks into an owned buffer.
    fn flatten(&self) -> Cow<'_, [u8]>;
}

impl ByteChunks for &[u8] {
    #[inline]
    fn feed_to<H: digest::Digest>(&self, hasher: &mut H) {
        digest::Digest::update(hasher, self);
    }

    #[inline]
    fn flatten(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<const N: usize> ByteChunks for &[u8; N] {
    #[inline]
    fn feed_to<H: digest::Digest>(&self, hasher: &mut H) {
        digest::Digest::update(hasher, *self);
    }

    #[inline]
    fn flatten(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_slice())
    }
}

impl ByteChunks for Vec<u8> {
    #[inline]
    fn feed_to<H: digest::Digest>(&self, hasher: &mut H) {
        digest::Digest::update(hasher, self);
    }

    #[inline]
    fn flatten(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<const N: usize> ByteChunks for [&[u8]; N] {
    #[inline]
    fn feed_to<H: digest::Digest>(&self, hasher: &mut H) {
        for chunk in self {
            digest::Digest::update(hasher, chunk);
        }
    }

    #[inline]
    fn flatten(&self) -> Cow<'_, [u8]> {
        let len: usize = self.iter().map(|c| c.len()).sum();
        let mut buf = Vec::with_capacity(len);
        for chunk in self {
            buf.extend_from_slice(chunk);
        }
        Cow::Owned(buf)
    }
}

/// Extension trait for hashers to accept [`ByteChunks`] inputs.
///
/// Provides `update_ext` and `chain_update_ext` as drop-in replacements
/// for `update` and `chain_update` that accept any [`ByteChunks`] implementor.
pub trait DigestExt: digest::Digest + Sized {
    /// Update the hasher with the given [`ByteChunks`].
    fn update_ext(&mut self, data: impl ByteChunks) {
        data.feed_to(self);
    }

    /// Update the hasher with the given [`ByteChunks`], returning `self` for chaining.
    fn chain_update_ext(mut self, data: impl ByteChunks) -> Self {
        self.update_ext(data);
        self
    }
}

impl<H: digest::Digest> DigestExt for H {}
