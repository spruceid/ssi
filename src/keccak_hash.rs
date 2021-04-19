use std::convert::TryFrom;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use keccak_hash::keccak;

use crate::error::Error;
use crate::jwk::{Params, JWK};

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
}
