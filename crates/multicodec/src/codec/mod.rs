use std::borrow::Cow;

use crate::Error;

pub trait Codec: Sized {
    const CODEC: u64;

    fn to_bytes(&self) -> Cow<[u8]>;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

pub trait MultiCodec: Sized {
    fn to_codec_and_bytes(&self) -> (u64, Cow<[u8]>);

    fn from_codec_and_bytes(codec: u64, bytes: &[u8]) -> Result<Self, Error>;
}

impl<C: Codec> MultiCodec for C {
    fn to_codec_and_bytes(&self) -> (u64, Cow<[u8]>) {
        (Self::CODEC, self.to_bytes())
    }

    fn from_codec_and_bytes(codec: u64, bytes: &[u8]) -> Result<Self, Error> {
        if codec == Self::CODEC {
            Self::from_bytes(bytes)
        } else {
            Err(Error::UnexpectedCodec(codec))
        }
    }
}

#[cfg(feature = "ed25519")]
mod ed25519;

#[cfg(feature = "k256")]
mod k256;

#[cfg(feature = "p256")]
mod p256;

#[cfg(feature = "p384")]
mod p384;

#[cfg(feature = "bls12-381")]
mod bls12_381;
