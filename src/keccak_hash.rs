use std::convert::TryFrom;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use keccak_hash::keccak;

use crate::error::Error;
use crate::jwk::{Params, JWK};

#[derive(thiserror::Error, Debug)]
pub enum HashPersonalMessageError {
    #[error("Message length conversion error: {0}")]
    Length(#[from] core::num::TryFromIntError),
}

pub fn bytes_to_lowerhex(bytes: &[u8]) -> String {
    "0x".to_string()
        + &bytes
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
}

pub fn hash_public_key(jwk: &JWK) -> Result<String, Error> {
    let ec_params = match jwk.params {
        Params::EC(ref params) => params,
        _ => return Err(Error::UnsupportedKeyType),
    };
    let pk = k256::PublicKey::try_from(ec_params)?;
    let pk_ec = pk.to_encoded_point(false);
    let pk_bytes = pk_ec.as_bytes();
    let hash = keccak(&pk_bytes[1..65]).to_fixed_bytes();
    let hash_last20 = &hash[12..32];
    let hash_last20_hex = bytes_to_lowerhex(hash_last20);
    Ok(hash_last20_hex)
}

pub fn hash_personal_message(msg: &str) -> Vec<u8> {
    let msg_bytes = msg.as_bytes();
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg_bytes.len());
    let data = [prefix.as_bytes().to_vec(), msg_bytes.to_vec()].concat();
    keccak(data).to_fixed_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash() {
        let jwk: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk",
            "y": "Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc",
        }))
        .unwrap();
        // https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020/blob/3b6dc297f92abc912049121c38c1098d819855d2/src/__tests__/ES256K-R.spec.js#L63
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74");
    }

    #[test]
    fn test_hash_personal_message() {
        let msg = "Hello world";
        let hash = hash_personal_message(msg);
        let hash_hex = bytes_to_lowerhex(&hash);
        assert_eq!(
            hash_hex,
            "0x8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede"
        );
    }
}
