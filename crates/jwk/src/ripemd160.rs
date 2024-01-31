use std::convert::TryFrom;

use crate::error::Error;
use crate::{Params, JWK};
use ssi_crypto::hashes::ripemd160;

/// Compute a hash of a public key as an ripemd160 hash.
pub fn hash_public_key(jwk: &JWK, version: u8) -> Result<String, Error> {
    let ec_params = match jwk.params {
        Params::EC(ref params) => params,
        _ => return Err(Error::UnsupportedKeyType),
    };
    let pk = k256::PublicKey::try_from(ec_params)?;
    Ok(ripemd160::hash_public_key(&pk, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ECParams;

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
