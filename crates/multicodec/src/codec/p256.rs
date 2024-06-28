use std::borrow::Cow;

use crate::{Codec, Error, P256_PUB};

impl Codec for p256::PublicKey {
    const CODEC: u64 = P256_PUB;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_sec1_bytes(bytes).map_err(|_| Error::InvalidData)
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.to_sec1_bytes().into_vec())
    }
}
