use std::borrow::Cow;

pub use zkryptium::bbsplus::keys::BBSplusPublicKey;

use crate::{Codec, Error, BLS12_381_G2_PUB};

impl Codec for BBSplusPublicKey {
    const CODEC: u64 = BLS12_381_G2_PUB;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        BBSplusPublicKey::from_bytes(bytes).map_err(|_| Error::InvalidData)
    }

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}
