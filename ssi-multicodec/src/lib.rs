use std::ops::Deref;

pub use unsigned_varint::decode::Error;

mod table;

pub use table::*;

/// Multi-encoded byte slice.
pub struct MultiEncoded([u8]);

impl MultiEncoded {
    /// Creates a new multi-encoded slice from the given `bytes`.
    ///
    /// Following the [`unsigned-varint`] specification and to avoid memory
    /// attacks, the coded must be encoded on at most 9 bytes (63 bits unsigned
    /// varint).
    ///
    /// [`unsigned-varint`](https://github.com/multiformats/unsigned-varint)
    #[inline(always)]
    pub fn new(bytes: &[u8]) -> Result<&Self, Error> {
        unsigned_varint::decode::u64(bytes)?;
        Ok(unsafe { std::mem::transmute(bytes) })
    }

    /// Creates a new multi-encoded slice from the given `bytes` without
    /// checking the codec.
    ///
    /// # Safety
    ///
    /// Following the [`unsigned-varint`] specification and to avoid memory
    /// attacks, the coded must be encoded on at most 9 bytes (63 bits unsigned
    /// varint).
    ///
    /// [`unsigned-varint`](https://github.com/multiformats/unsigned-varint)
    #[inline(always)]
    pub unsafe fn new_unchecked(bytes: &[u8]) -> &Self {
        unsafe { std::mem::transmute(bytes) }
    }

    #[inline(always)]
    pub fn parts(&self) -> (u64, &[u8]) {
        unsigned_varint::decode::u64(&self.0).unwrap()
    }

    #[inline(always)]
    pub fn codec(&self) -> u64 {
        self.parts().0
    }

    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        self.parts().1
    }
}

pub struct MultiEncodedBuf(Vec<u8>);

impl MultiEncodedBuf {
    /// Creates a new multi-encoded slice from the given `bytes`.
    ///
    /// Following the [`unsigned-varint`] specification and to avoid memory
    /// attacks, the coded must be encoded on at most 9 bytes (63 bits unsigned
    /// varint).
    ///
    /// [`unsigned-varint`](https://github.com/multiformats/unsigned-varint)
    #[inline(always)]
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        unsigned_varint::decode::u64(&bytes)?;
        Ok(Self(bytes))
    }

    /// Creates a new multi-encoded slice from the given `bytes` without
    /// checking the codec.
    ///
    /// # Safety
    ///
    /// Following the [`unsigned-varint`] specification and to avoid memory
    /// attacks, the coded must be encoded on at most 9 bytes (63 bits unsigned
    /// varint).
    ///
    /// [`unsigned-varint`](https://github.com/multiformats/unsigned-varint)
    #[inline(always)]
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[inline(always)]
    pub fn as_multi_encoded(&self) -> &MultiEncoded {
        unsafe { MultiEncoded::new_unchecked(&self.0) }
    }
}

impl Deref for MultiEncodedBuf {
    type Target = MultiEncoded;

    fn deref(&self) -> &Self::Target {
        self.as_multi_encoded()
    }
}
