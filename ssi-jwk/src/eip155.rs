use crate::{Error, Params, JWK};
use ssi_crypto::hashes::keccak;

/// Compute a hash of a public key as an Ethereum address.
///
/// The hash is of the public key (64 bytes), using Keccak. The hash is truncated to the last 20
/// bytes, lowercase-hex-encoded, and prefixed with "0x" to form the resulting string.
pub fn hash_public_key(jwk: &JWK) -> Result<String, Error> {
    let ec_params = match jwk.params {
        Params::EC(ref params) => params,
        _ => return Err(Error::UnsupportedKeyType),
    };
    let pk = k256::PublicKey::try_from(ec_params)?;
    Ok(keccak::hash_public_key(&pk))
}

/// Compute a hash of a public key as an Ethereum address, with EIP-55 checksum.
///
/// Same as [`hash_public_key_lowercase`], but with [EIP-55] mixed-case checksum encoding (using [`eip55_checksum_addr`]).
/// [EIP-55]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
pub fn hash_public_key_eip55(jwk: &JWK) -> Result<String, Error> {
    let hash_lowercase = hash_public_key(jwk)?;
    Ok(keccak::eip55_checksum_addr(&hash_lowercase)?)
}
