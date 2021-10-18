use std::convert::TryFrom;

use crate::error::Error;
use crate::hash::sha256;
use crate::jwk::{Params, JWK};

use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd160::{Digest, Ripemd160};

pub fn hash_public_key(jwk: &JWK, version: u8) -> Result<String, Error> {
    let ec_params = match jwk.params {
        Params::EC(ref params) => params,
        _ => return Err(Error::UnsupportedKeyType),
    };
    let pk = k256::PublicKey::try_from(ec_params)?;
    let pk_bytes = pk.to_encoded_point(true);
    if pk_bytes.len() != 33 {
        return Err(Error::UnsupportedKeyType);
    }
    let pk_sha256 = sha256(pk_bytes.as_bytes())?;
    let pk_ripemd160 = Ripemd160::digest(&pk_sha256);
    let mut extended_ripemd160 = Vec::with_capacity(21);
    extended_ripemd160.extend_from_slice(&[version]);
    extended_ripemd160.extend_from_slice(&pk_ripemd160);
    let addr = bs58::encode(&extended_ripemd160).with_check().into_string();
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::ECParams;

    #[test]
    fn hash() {
        // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
        let pk_hex = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let pk = k256::PublicKey::from_sec1_bytes(&pk_bytes).unwrap();
        let jwk = JWK {
            params: Params::EC(ECParams::try_from(&pk).unwrap()),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let hash = hash_public_key(&jwk, 0).unwrap();
        assert_eq!(hash, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
    }
}
