use std::borrow::Cow;

use crate::{Codec, Error, ED25519_PUB};
use ed25519_dalek::VerifyingKey;

impl Codec for VerifyingKey {
    const CODEC: u64 = ED25519_PUB;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::try_from(bytes).map_err(|_| Error::InvalidData)
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes().as_slice())
    }
}
