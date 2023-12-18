use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;

use crate::Error;

#[derive(FromPrimitive, ToPrimitive)]
pub enum Codec {
    Secp256k1Pub = 0xe7,
    Ed25519Pub = 0xed,
    P256Pub = 0x1200,
    P384Pub = 0x1201,
    P521Pub = 0x1202,
    RSAPub = 0x1205,
    Ed25519Priv = 0x1300,
    Secp256k1Priv = 0x1301,
    RSAPriv = 0x1305,
    P256Priv = 0x1306,
    P384Priv = 0x1307,
    P521Priv = 0x1308,
}

pub fn decode(data: &[u8]) -> Result<(Codec, Vec<u8>), Error> {
    match unsigned_varint::decode::usize(data) {
        Ok((c, data)) => match Codec::from_usize(c) {
            Some(codec) => Ok((codec, data.to_vec())),
            None => Err(Error::MultibaseKeyPrefix),
        },
        Err(_) => Err(Error::MultibaseKeyPrefix),
    }
}
