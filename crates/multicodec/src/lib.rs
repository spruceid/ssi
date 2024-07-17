use std::ops::Deref;

mod codec;
pub use codec::*;

include!(concat!(env!("OUT_DIR"), "/table.rs"));

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::decode::Error),

    #[error("unexpected codec {0}")]
    UnexpectedCodec(u64),

    #[error("invalid data")]
    InvalidData,
}

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
        Ok(unsafe { std::mem::transmute::<&[u8], &Self>(bytes) })
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

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
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

    /// Returns the raw bytes, including the codec prefix.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    pub fn decode<T: MultiCodec>(&self) -> Result<T, Error> {
        let (codec, bytes) = self.parts();
        T::from_codec_and_bytes(codec, bytes)
    }
}

#[derive(Clone)]
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

    pub fn encode_bytes(codec: u64, bytes: &[u8]) -> Self {
        let mut codec_buffer = [0u8; 10];
        let encoded_codec = unsigned_varint::encode::u64(codec, &mut codec_buffer);
        let mut result = Vec::with_capacity(encoded_codec.len() + bytes.len());
        result.extend(encoded_codec);
        result.extend(bytes);
        Self(result)
    }

    pub fn encode<T: MultiCodec>(value: &T) -> Self {
        let (codec, bytes) = value.to_codec_and_bytes();
        Self::encode_bytes(codec, &bytes)
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

    /// Returns the raw bytes, including the codec prefix.
    #[inline(always)]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for MultiEncodedBuf {
    type Target = MultiEncoded;

    fn deref(&self) -> &Self::Target {
        self.as_multi_encoded()
    }
}

impl AsRef<[u8]> for MultiEncodedBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
