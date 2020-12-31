use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Error;
use crate::jwk::{Algorithm, JWK};

// RFC 7519 - JSON Web Token (JWT)

pub fn encode_sign<Claims: Serialize>(
    algorithm: Algorithm,
    claims: &Claims,
    key: &JWK,
) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    crate::jws::encode_sign(algorithm, &payload, key)
}

pub fn encode_unsigned<Claims: Serialize>(claims: &Claims) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    crate::jws::encode_unsigned(&payload)
}

pub fn decode_verify<Claims: DeserializeOwned>(jwt: &str, key: &JWK) -> Result<Claims, Error> {
    let (_header, payload) = crate::jws::decode_verify(jwt, key)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}

// for vc-test-suite
pub fn decode_unverified<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims, Error> {
    let (_header, payload) = crate::jws::decode_unverified(jwt)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}
