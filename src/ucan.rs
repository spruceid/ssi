use crate::{
    did::{Document, Resource, VerificationMethod, VerificationMethodMap},
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
use serde_with::{serde_as, DisplayFromStr};
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

impl<F, A> DecodedUcanTree<F, A> {
    pub fn validate_time(&self, time: Option<f64>) -> Result<(), TimeInvalid> {
        let t = Some(time.unwrap_or_else(now));
        self.ucan.payload.validate_time(t)?;
        self.parents
            .iter()
            .map(|p| p.validate_time(t))
            .collect::<Result<Vec<()>, TimeInvalid>>()?;
        Ok(())
    }
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    pub async fn decode_verify(jwt: &str, resolver: &dyn DIDResolver) -> Result<Self, Error>
    where
        F: DeserializeOwned + Send,
        A: DeserializeOwned + Send,
    {
        let parts = split_jws(jwt).and_then(|(h, p, s)| decode_jws_parts(h, p.as_bytes(), s))?;
        let payload: Payload<F, A> = serde_json::from_slice(&parts.payload)?;

        if parts.header.type_.as_deref() != Some("JWT") {
            return Err(Error::MissingType);
        }

        match parts.header.additional_parameters.get("ucv") {
            Some(JsonValue::String(v)) if v == "0.8.1" => (),
            _ => return Err(Error::MissingType),
        }

        if !payload.audience.starts_with("did:") {
            return Err(Error::DIDURL);
        }

        // extract or deduce signing key
        let key: JWK = match (
            payload.issuer.get(..8),
            &parts.header.jwk,
            dereference(resolver, &payload.issuer, &Default::default())
                .await
                .1,
        ) {
            // did:pkh without fragment
            (Some("did:pkh:"), Some(jwk), Content::DIDDocument(d)) => {
                match_key_with_did_pkh(jwk, &d)?;
                jwk.clone()
            }
            // did:pkh with fragment
            (Some("did:pkh:"), Some(jwk), Content::Object(Resource::VerificationMethod(vm))) => {
                match_key_with_vm(jwk, &vm)?;
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
                .ok_or(Error::VerificationMethodMismatch)?
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
}

impl<F, A> Ucan<F, A> {
    pub async fn decode_verify(jwt: &str, resolver: &dyn DIDResolver) -> Result<Ucan<F, A>, Error>
    where
        F: DeserializeOwned + Send,
        A: DeserializeOwned + Send,
    {
        Ok(DecodedUcanTree::decode_verify(jwt, resolver).await?.ucan)
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

fn match_key_with_did_pkh(key: &JWK, doc: &Document) -> Result<(), Error> {
    doc.verification_method
        .iter()
        .flatten()
        .find_map(|vm| match vm {
            VerificationMethod::Map(vm) if vm.blockchain_account_id.is_some() => {
                Some(match_key_with_vm(key, vm))
            }
            _ => None,
        })
        .unwrap_or(Err(Error::VerificationMethodMismatch))
}

fn match_key_with_vm(key: &JWK, vm: &VerificationMethodMap) -> Result<(), Error> {
    use std::str::FromStr;
    Ok(crate::caip10::BlockchainAccountId::from_str(
        vm.blockchain_account_id
            .as_ref()
            .ok_or(Error::VerificationMethodMismatch)?,
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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
    pub facts: Option<Vec<F>>,
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

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum UcanResource {
    Proof(#[serde_as(as = "DisplayFromStr")] UcanProofRef),
    URI(URI),
}

#[derive(Clone, PartialEq, Debug)]
pub struct UcanProofRef(pub u64);

impl std::fmt::Display for UcanProofRef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "prf/{}", self.0)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProofRefParseErr {
    #[error("Missing prf prefix")]
    Format,
    #[error("Invalid Integer reference")]
    ParseInt(#[from] std::num::ParseIntError),
}

impl std::str::FromStr for UcanProofRef {
    type Err = ProofRefParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UcanProofRef(
            s.strip_prefix("prf/")
                .map(u64::from_str)
                .ok_or(ProofRefParseErr::Format)??,
        ))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct UcanScope {
    pub namespace: String,
    pub capability: String,
}

impl std::fmt::Display for UcanScope {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.capability)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UcanScopeParseErr {
    #[error("Missing namespace")]
    Namespace,
}

impl std::str::FromStr for UcanScope {
    type Err = UcanScopeParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns, cap) = s.split_once('/').ok_or(UcanScopeParseErr::Namespace)?;
        Ok(UcanScope {
            namespace: ns.to_string(),
            capability: cap.to_string(),
        })
    }
}

/// 3.2.5 A JSON capability MUST include the with and can fields and
/// MAY have additional fields needed to describe the capability
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Capability<A = HashMap<String, JsonValue>> {
    pub with: UcanResource,
    #[serde_as(as = "DisplayFromStr")]
    pub can: UcanScope,
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
    async fn valid() {
        let cases: Vec<ValidTestVector> =
            serde_json::from_str(include_str!("../tests/ucan-v0.8.1-valid.json")).unwrap();
        for case in cases {
            let ucans = match DecodedUcanTree::<JsonValue>::decode_verify(
                &case.token,
                DIDExample.to_resolver(),
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    println!("{}", case.comment);
                    Err(e).unwrap()
                }
            };

            // assert!(ucans.validate_time(None).is_ok());
            assert_eq!(ucans.ucan.payload, case.assertions.payload);
            assert_eq!(ucans.ucan.header, case.assertions.header);
        }
    }

    #[async_std::test]
    async fn invalid() {
        let cases: Vec<InvalidTestVector> =
            serde_json::from_str(include_str!("../tests/ucan-v0.8.1-invalid.json")).unwrap();
        for case in cases {
            match DecodedUcanTree::<JsonValue>::decode_verify(&case.token, DIDExample.to_resolver())
                .await
            {
                Ok(u) => {
                    if u.validate_time(None).is_ok() {
                        assert!(false, "{}", case.comment);
                    }
                }
                Err(_e) => {}
            };
        }
    }

    #[derive(Deserialize)]
    struct ValidAssertions {
        pub header: Header,
        pub payload: Payload,
    }

    #[derive(Deserialize)]
    struct ValidTestVector {
        pub comment: String,
        pub token: String,
        pub assertions: ValidAssertions,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InvalidAssertions {
        pub header: Option<JsonValue>,
        pub payload: Option<JsonValue>,
        pub type_errors: Option<Vec<String>>,
        pub validation_errors: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    struct InvalidTestVector {
        pub comment: String,
        pub token: String,
        pub assertions: InvalidAssertions,
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
            "key"
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
