use crate::vc::URI;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{collections::HashMap, convert::TryFrom};

pub struct UCAN<S = Vec<u8>, F = JsonValue, A = HashMap<String, JsonValue>> {
    pub header: Header,
    pub payload: Payload<F, A>,
    pub signature: S,
    // to preserve exact signed bytes in case of out-of-order
    // fields when deserialising
    // ugh setting this during "b64_encode" will require &mut self :(
    // signed_data: Vec<u8>,
}

impl<S, F, A> UCAN<S, F, A>
where
    S: AsRef<[u8]>,
    F: Serialize,
    A: Serialize,
{
    pub fn b64_encode(&self) -> Result<String, serde_json::Error> {
        Ok([
            b64encode(&serde_json::to_vec(&self.header)?),
            b64encode(&serde_json::to_vec(&self.payload)?),
            b64encode(&self.signature),
        ]
        .join("."))
    }
}

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

impl<'de, S, F, A> UCAN<S, F, A>
where
    S: TryFrom<Vec<u8>>,
    F: Deserialize<'de>,
    A: Deserialize<'de>,
{
    pub fn b64_decode(b64: &str) -> Result<Self, DecodeError<S::Error>> {
        use serde_json::from_slice;

        let mut parts = b64.split('.').map(b64decode);
        let header = from_slice(&parts.next().transpose()?.ok_or(DecodeError::Form)?)?;
        let payload = from_slice(&parts.next().transpose()?.ok_or(DecodeError::Form)?)?;
        let signature = S::try_from(parts.next().transpose()?.ok_or(DecodeError::Form)?)
            .map_err(DecodeError::Signature)?;

        if parts.next() != None {
            Err(DecodeError::Form)
        } else {
            Ok(Self {
                header,
                payload,
                signature,
            })
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Payload<F = JsonValue, A = HashMap<String, JsonValue>> {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    #[serde(rename = "exp")]
    pub expiration: u64,
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
    pub fn validate_time(&self, time: Option<u64>) -> Result<(), TimeInvalid> {
        let t = time.unwrap_or_else(now);
        match (self.not_before, t > self.expiration) {
            (_, true) => Err(TimeInvalid::TooLate),
            (Some(nbf), _) if t < nbf => Err(TimeInvalid::TooEarly),
            _ => Ok(()),
        }
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

/// 3.1 Header
/// The header is a standard JWT header, with an additional REQUIRED field ucv.
/// This field sets the version of the UCAN specification used in the payload.
#[derive(Serialize, Deserialize, Clone)]
pub struct Header {
    #[serde(rename = "alg")]
    algorithm: String,
    typ: Typ,
    ucv: UCV,
}

impl Header {
    pub fn new(alg: &str) -> Self {
        Self {
            algorithm: alg.to_string(),
            typ: Typ::JWT,
            ucv: UCV::V0_8_1,
        }
    }
    pub fn version(&self) -> &str {
        "0.8.1"
    }
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}

#[derive(Serialize, Deserialize, Clone)]
enum Typ {
    JWT,
}

#[derive(Serialize, Deserialize, Clone)]
enum UCV {
    #[serde(rename = "0.8.1")]
    V0_8_1,
}

fn b64encode<D: AsRef<[u8]>>(d: &D) -> String {
    base64::encode_config(d.as_ref(), base64::URL_SAFE_NO_PAD)
}

fn b64decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(s, base64::URL_SAFE_NO_PAD)
}

fn now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    use instant::SystemTime;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn header() {
    let h = Header::new("alg");
    assert_eq!(
        serde_json::to_string(&h).unwrap(),
        r#"{"alg":"alg","typ":"JWT","ucv":"0.8.1"}"#
    );
}
