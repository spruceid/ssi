use crate::{
    error::Error,
    jwk::{Algorithm, JWK},
    jws::{encode_sign_custom_header, Header},
    jwt::decode_verify,
    vc::{NumericDate, URI},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

#[derive(thiserror::Error, Debug)]
pub enum DecodeError<E> {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid JWT Structure")]
    Form,
    #[error(transparent)]
    Signature(E),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Payload<F = JsonValue, A = HashMap<String, JsonValue>> {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<NumericDate>,
    #[serde(rename = "exp")]
    pub expiration: NumericDate,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(rename = "fct", skip_serializing_if = "Option::is_none")]
    pub facts: Option<F>,
    #[serde(rename = "prf")]
    pub proof: Vec<String>,
    #[serde(rename = "att")]
    pub attenuation: Vec<Capability<A>>,
}

#[derive(thiserror::Error, Debug)]
pub enum TimeInvalid {
    #[error("UCAN not yet valid")]
    TooEarly,
    #[error("UCAN has expired")]
    TooLate,
}

impl<F, A> Payload<F, A> {
    pub fn validate_time(&self, time: Option<f64>) -> Result<(), TimeInvalid> {
        let t = time.unwrap_or_else(now);
        match (self.not_before, t > self.expiration.as_seconds()) {
            (_, true) => Err(TimeInvalid::TooLate),
            (Some(nbf), _) if t < nbf.as_seconds() => Err(TimeInvalid::TooEarly),
            _ => Ok(()),
        }
    }

    // NOTE IntoIter::new is deprecated, but into_iter() returns references until we move to 2021 edition
    #[allow(deprecated)]
    pub fn encode_sign(&self, algorithm: Algorithm, key: &JWK) -> Result<String, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        encode_sign_custom_header(
            &serde_json::to_string(&self)?,
            key,
            &Header {
                algorithm,
                key_id: key.key_id.clone(),
                type_: Some("JWT".to_string()),
                additional_parameters: std::array::IntoIter::new([(
                    "ucv".to_string(),
                    serde_json::Value::String("0.8.1".to_string()),
                )])
                .collect(),
                ..Default::default()
            },
        )
    }

    pub fn decode_verify(jwt: &str, key: &JWK) -> Result<Self, Error>
    where
        F: DeserializeOwned,
        A: DeserializeOwned,
    {
        let p = decode_verify(jwt, key)?;
        // TODO check that the issuing key matches/is part of the DID Doc
        Ok(p)
    }
}

/// 3.2.5 A JSON capability MUST include the with and can fields and
/// MAY have additional fields needed to describe the capability
#[derive(Serialize, Deserialize, Clone)]
pub struct Capability<A = HashMap<String, JsonValue>> {
    pub with: URI,
    pub can: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub additional_fields: Option<A>,
}

fn now() -> f64 {
    #[cfg(target_arch = "wasm32")]
    use instant::SystemTime;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64
}
