use crate::{
    did::{Resource, VerificationMethod},
    did_resolve::{dereference, Content, DIDResolver},
    error::Error,
    jwk::{Algorithm, JWK},
    jws::{decode_jws_parts, encode_sign_custom_header, split_jws, verify_bytes, Header},
    vc::{NumericDate, URI},
};
use async_recursion::async_recursion;
use futures::future::try_join_all;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

#[derive(Clone, PartialEq)]
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
            payload.issuer.get(..8),
            &parts.header.jwk,
            dereference(resolver, &payload.issuer, &Default::default())
                .await
                .1,
        ) {
            // did:pkh with and without fragment
            (Some("did:pkh:"), Some(jwk), Content::Object(_) | Content::DIDDocument(_)) => {
                match_key_with_did_pkh(&jwk, &payload.issuer)?;
                jwk.clone()
            }
            // did:key without fragment
            (Some("did:key:"), _, Content::DIDDocument(d)) => d
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

        let parents = try_join_all(
            payload
                .proof
                .iter()
                .map(|s| Self::decode_verify(s, resolver)),
        )
        .await?;

        if parents
            .iter()
            .any(|p| p.ucan.payload.audience != payload.issuer)
        {
            return Err(Error::InvalidIssuer);
        }

        Ok(DecodedUcanTree {
            // decode and verify parents
            parents,
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

fn match_key_with_did_pkh(key: &JWK, did: &str) -> Result<(), Error> {
    use std::str::FromStr;
    Ok(crate::caip10::BlockchainAccountId::from_str(
        did.split_once('#')
            .map(|(d, _)| d)
            .unwrap_or(did)
            .strip_prefix("did:pkh:")
            .ok_or(Error::DIDURL)?,
    )?
    .verify(key)?)
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

#[derive(Serialize, Deserialize, Clone, PartialEq)]
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
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Capability<A = HashMap<String, JsonValue>> {
    pub with: URI,
    pub can: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub additional_fields: Option<A>,
}

fn now() -> f64 {
    (chrono::prelude::Utc::now().timestamp_nanos() as f64) / 1e+9_f64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[async_std::test]
    async fn rights_amplification() {
        let s = r#"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOC4xIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWtmZ3RYa0NuYjlMWG44Qm55anhSTW5LdEZnWmM3NE02ODczdjYxcUNjS0hqayIsImF1ZCI6ImRpZDprZXk6ejZNa2dYNWpqUlVidHlzZ2dFNHJhQ2FxQ1g4OEF6U3ZZcTgxV0prQm9BMW90OGFlIiwiZXhwIjo0ODA0MTQzNDEyLCJhdHQiOltdLCJwcmYiOltdfQ.NaguDFWi8SkedAZ5eplUvQgMkeIQyZLzvl6084mH4vxqTazMxyDbT8RdHGumGug2NmKSvHn0_t2ae0KJK5U-BQ"#;
        Ucan::<JsonValue>::decode_verify(s, DIDExample.to_resolver())
            .await
            .unwrap();
    }

    #[async_std::test]
    async fn issuer_matches_delegate() {
        let s = r#"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOC4xIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWtmZ3RYa0NuYjlMWG44Qm55anhSTW5LdEZnWmM3NE02ODczdjYxcUNjS0hqayIsImF1ZCI6ImRpZDprZXk6ejZNa2dYNWpqUlVidHlzZ2dFNHJhQ2FxQ1g4OEF6U3ZZcTgxV0prQm9BMW90OGFlIiwiZXhwIjo0ODA0MTQzNDEyLCJhdHQiOltdLCJwcmYiOlsiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNklrcFhWQ0lzSW5WamRpSTZJakF1T0M0eEluMC5leUpwYzNNaU9pSmthV1E2YTJWNU9ubzJUV3R4Ym1KT2FUbDJaSFJFTkVSTFVXaHlTREpaUjFkMFFtZDNRak51TkRFeVFWRlVPRXhuVWpkQk5qZEZSeUlzSW1GMVpDSTZJbVJwWkRwclpYazZlalpOYTJabmRGaHJRMjVpT1V4WWJqaENibmxxZUZKTmJrdDBSbWRhWXpjMFRUWTROek4yTmpGeFEyTkxTR3BySWl3aVpYaHdJam8wT0RBME1UUXpOREV5TENKaGRIUWlPbHRkTENKd2NtWWlPbHRkZlEuTUFudEhWZFVxZVc5N3Y0RVByU0pqWjBQOUdjTExGaEZJZEVZRUhBZG12NHgyQ0RmbnRVYXFEekFnTUN4d0tDTkJDQVhCRnZ5MUFUMTVaRkhzMDIyQVEiXX0.TA5ugLsiu7jrK3y9fzrLFNuaqnzFSA8ogjvwUS84_pEi8xYk2fGC7LhOQCo0DuMqvlT9ubYp3ywGizHlZ0waAA"#;
        Ucan::<JsonValue>::decode_verify(s, DIDExample.to_resolver())
            .await
            .unwrap();
    }

    #[async_std::test]
    async fn versions_match() {
        let s = r#"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOC4xIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWtmZ3RYa0NuYjlMWG44Qm55anhSTW5LdEZnWmM3NE02ODczdjYxcUNjS0hqayIsImF1ZCI6ImRpZDprZXk6ejZNa2dYNWpqUlVidHlzZ2dFNHJhQ2FxQ1g4OEF6U3ZZcTgxV0prQm9BMW90OGFlIiwiZXhwIjo0ODA0MTQzNDEyLCJhdHQiOltdLCJwcmYiOlsiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNklrcFhWQ0lzSW5WamRpSTZJakF1T0M0eEluMC5leUpwYzNNaU9pSmthV1E2YTJWNU9ubzJUV3RtYm0xa1NEaHpUbTFEYUZWemEyaFJia3REVGpKTmNHaE5RMHhtUVcxU1FVYzBhVzlOZGtKV2RGRjFWaUlzSW1GMVpDSTZJbVJwWkRwclpYazZlalpOYTJabmRGaHJRMjVpT1V4WWJqaENibmxxZUZKTmJrdDBSbWRhWXpjMFRUWTROek4yTmpGeFEyTkxTR3BySWl3aVpYaHdJam8wT0RBME1UUXpOREV5TENKaGRIUWlPbHRkTENKd2NtWWlPbHRkZlEub2NURHU5emlkMW11NG9qOVJkVDRwMzdudlRPbEh1aWZkLW9EamZUTjF1ZHJaWnhpRjJiNUJKYmNzNGtEU0tKaU91enExT1hEVUctay1JOXNGdlMwQmciXX0.ok2xB1mr04nShwF76rgdBgv5dnUrbpAacMHXkOJCP-0kqvO4GYOwhLDwW6j43mnD2XCvy4U20LTTh_mkumxYAQ"#;
        Ucan::<JsonValue>::decode_verify(s, DIDExample.to_resolver())
            .await
            .unwrap();
    }

    #[async_std::test]
    async fn not_expired() {
        let s = r#"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOC4xIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWtmZ3RYa0NuYjlMWG44Qm55anhSTW5LdEZnWmM3NE02ODczdjYxcUNjS0hqayIsImF1ZCI6ImRpZDprZXk6ejZNa2dYNWpqUlVidHlzZ2dFNHJhQ2FxQ1g4OEF6U3ZZcTgxV0prQm9BMW90OGFlIiwiZXhwIjo0ODA0MTQzNDEyLCJhdHQiOltdLCJwcmYiOltdfQ.NaguDFWi8SkedAZ5eplUvQgMkeIQyZLzvl6084mH4vxqTazMxyDbT8RdHGumGug2NmKSvHn0_t2ae0KJK5U-BQ"#;
        Ucan::<JsonValue>::decode_verify(s, DIDExample.to_resolver())
            .await
            .unwrap();
    }

    pub struct DIDExample;
    use crate::did::{DIDMethod, Document};
    use crate::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
    };
    use async_trait::async_trait;

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDMethod for DIDExample {
        fn name(&self) -> &'static str {
            return "key";
        }
        fn to_resolver(&self) -> &dyn DIDResolver {
            self
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDResolver for DIDExample {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            let dids: HashMap<String, Document> =
                serde_json::from_str(include_str!("../tests/did-key-statics.json")).unwrap();
            let doc: Document = match dids.get(did) {
                Some(doc) => doc.clone(),
                _ => {
                    return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None);
                }
            };
            (
                // ResolutionMetadata::default(),
                // Note: remove content type when https://github.com/spruceid/ssi/pull/224 is
                // merged
                ResolutionMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        }
    }
}
