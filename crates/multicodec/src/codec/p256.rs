use std::borrow::Cow;

use crate::{Codec, Error, P256_PRIV, P256_PUB};

impl Codec for p256::PublicKey {
    const CODEC: u64 = P256_PUB;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_sec1_bytes(bytes).map_err(|_| Error::InvalidData)
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        Cow::Owned(self.to_encoded_point(true).as_bytes().to_vec())
    }
}

impl Codec for p256::SecretKey {
    const CODEC: u64 = P256_PRIV;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes).map_err(|_| Error::InvalidData)
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}
