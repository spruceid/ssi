use crate::{Params, JWK};
use ssi_crypto::{hashes::keccak, k256, key::KeyConversionError};

/// Compute a hash of a public key as an Ethereum address.
///
/// The hash is of the public key (64 bytes), using Keccak. The hash is truncated to the last 20
/// bytes, lowercase-hex-encoded, and prefixed with "0x" to form the resulting string.
pub fn hash_public_key(jwk: &JWK) -> Result<String, KeyConversionError> {
    let ec_params = match jwk.params {
        Params::Ec(ref params) => params,
        _ => return Err(KeyConversionError::Unsupported),
    };

    let pk = k256::PublicKey::try_from(ec_params)?;

    Ok(keccak::hash_public_key(&pk))
}

/// Compute a hash of a public key as an Ethereum address, with [EIP-55] checksum.
///
/// [EIP-55]: <https://eips.ethereum.org/EIPS/eip-55>
pub fn hash_public_key_eip55(jwk: &JWK) -> Result<String, KeyConversionError> {
    let hash_lowercase = hash_public_key(jwk)?;
    keccak::eip55_checksum_addr(&hash_lowercase).map_err(|_| KeyConversionError::Invalid)
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
