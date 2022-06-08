use crate::{
    did::{Resource, VerificationMethod},
    did_resolve::{dereference, Content, DIDResolver},
    error::Error,
    jwk::{Algorithm, JWK},
    jws::{decode_jws_parts, encode_sign_custom_header, split_jws, verify_bytes, Header},
    jwt::decode_verify,
    vc::{NumericDate, URI},
};
use async_recursion::async_recursion;
use futures::future::try_join_all;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Ucan<F = JsonValue, A = HashMap<String, JsonValue>> {
    pub header: Header,
    pub payload: Payload<F, A>,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct DecodedUcanTree<F = JsonValue, A = HashMap<String, JsonValue>> {
    pub ucan: Ucan<F, A>,
    pub parents: Vec<DecodedUcanTree<F, A>>,
}

impl<F, A> Ucan<F, A> {
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    pub async fn decode_verify(
        jwt: &str,
        resolver: &dyn DIDResolver,
    ) -> Result<DecodedUcanTree<F, A>, Error>
    where
        F: DeserializeOwned + Send,
        A: DeserializeOwned + Send,
    {
        let parts = split_jws(jwt).and_then(|(h, p, s)| decode_jws_parts(h, p.as_bytes(), s))?;
        let payload: Payload<F, A> = serde_json::from_slice(&parts.payload)?;

        // extract or deduce signing key
        let key: JWK = match (
            payload.issuer.split(':').nth(1),
            &parts.header.jwk,
            dereference(resolver, &payload.issuer, &Default::default())
                .await
                .1,
        ) {
            // did:pkh with and without fragment
            (Some("pkh"), Some(jwk), Content::DIDDocument(_) | Content::Object(_)) => jwk.clone(),
            // did:key without fragment
            (Some("key"), _, Content::DIDDocument(d)) => d
                .verification_method
                .iter()
                .flatten()
                .next()
                .and_then(|v| match v {
                    VerificationMethod::Map(vm) => Some(vm),
                    _ => None,
                })
                .ok_or_else(|| Error::VerificationMethodMismatch)?
                .get_jwk()?,
            // general case, did with fragment
            (Some(_), _, Content::Object(Resource::VerificationMethod(vm))) => vm.get_jwk()?,
            _ => return Err(Error::VerificationMethodMismatch),
        };

        verify_bytes(
            parts.header.algorithm,
            &parts.signing_input,
            &key,
            &parts.signature,
        )?;

        Ok(DecodedUcanTree {
            // decode and verify parents
            parents: try_join_all(
                payload
                    .proof
                    .iter()
                    .map(|s| Self::decode_verify(s, resolver)),
            )
            .await?,
            ucan: Ucan {
                header: parts.header,
                payload,
                signature: parts.signature,
            },
        })
    }

    pub fn decode(jwt: &str) -> Result<Self, Error>
    where
        F: DeserializeOwned,
        A: DeserializeOwned,
    {
        let parts = split_jws(jwt).and_then(|(h, p, s)| decode_jws_parts(h, p.as_bytes(), s))?;
        let payload: Payload<F, A> = serde_json::from_slice(&parts.payload)?;
        Ok(Self {
            header: parts.header,
            payload,
            signature: parts.signature,
        })
    }

    pub fn parents(&self) -> ParentIter {
        self.payload.parents()
    }
}

pub struct ParentIter<'a>(std::slice::Iter<'a, String>);

impl<'a> Iterator for ParentIter<'a> {
    type Item = Result<Ucan, Error>;
    fn next(&mut self) -> Option<Result<Ucan, Error>> {
        self.0.next().map(|s| Ucan::decode(s))
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

    pub fn parents(&self) -> ParentIter {
        ParentIter(self.proof.iter())
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
        .as_secs_f64()
}
