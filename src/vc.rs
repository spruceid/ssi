use std::collections::HashMap as Map;
use std::convert::TryFrom;

use crate::error::Error;
use crate::jwk::{JWTKeys, Params};

use chrono::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ********************************************
// * Data Structures for Verifiable Credentials
// * W3C Editor's Draft 15 January 2020
// * https://w3c.github.io/vc-data-model/
// ********************************************
// @TODO items:
// - implement HS256 and ES256 (RFC 7518) for JWT
// - more complete URI checking
// - decode Presentation from JWT
// - ensure refreshService id and credentialStatus id are URLs
// - implement IntoIterator for OneOrMany, instead of using own
//   functions for any, len, contains, etc.
// - Decode JWT VC embedded in VP

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

// work around https://github.com/w3c/vc-test-suite/issues/103
pub const ALT_DEFAULT_CONTEXT: &str = "https://w3.org/2018/credentials/v1";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,
    pub credential_subject: OneOrMany<Subject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Issuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<DateTime<Utc>>, // must be RFC3339
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>, // must be RFC3339
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<Vec<TermsOfUse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<OneOrMany<Evidence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<OneOrMany<Schema>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<OneOrMany<RefreshService>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<Context>")]
pub enum Contexts {
    One(Context),
    Many(Vec<Context>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Context {
    URI(URI),
    Object(Map<String, Value>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Issuer {
    URI(URI),
    Object(ObjectWithId),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWithId {
    pub id: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
#[serde(untagged)]
pub enum URI {
    String(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,
    pub verifiable_credential: OneOrMany<CredentialOrJWT>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<URI>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum CredentialOrJWT {
    Credential(Credential),
    JWT(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exp")]
    pub expiration_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iss")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "nbf")]
    pub not_before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sub")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "aud")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vc")]
    pub verifiable_credential: Option<Credential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vp")]
    pub verifiable_presentation: Option<Presentation>,
}

impl<T> OneOrMany<T> {
    pub fn any<F>(&self, f: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        match self {
            Self::One(value) => f(value),
            Self::Many(values) => values.iter().any(f),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }

    pub fn contains(&self, x: &T) -> bool
    where
        T: PartialEq<T>,
    {
        match self {
            Self::One(value) => x == value,
            Self::Many(values) => values.contains(x),
        }
    }

    pub fn first(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(&value),
            Self::Many(values) => {
                if values.len() > 0 {
                    Some(&values[0])
                } else {
                    None
                }
            }
        }
    }

    pub fn to_single(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(&value),
            Self::Many(values) => {
                if values.len() == 1 {
                    Some(&values[0])
                } else {
                    None
                }
            }
        }
    }
}

impl TryFrom<OneOrMany<Context>> for Contexts {
    type Error = Error;
    fn try_from(context: OneOrMany<Context>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err(Error::MissingContext),
            Some(Context::URI(URI::String(uri))) => uri,
            Some(Context::Object(_)) => return Err(Error::InvalidContext),
        };
        if first_uri != DEFAULT_CONTEXT && first_uri != ALT_DEFAULT_CONTEXT {
            return Err(Error::InvalidContext);
        }
        Ok(match context {
            OneOrMany::One(context) => Contexts::One(context),
            OneOrMany::Many(contexts) => Contexts::Many(contexts),
        })
    }
}

impl From<Contexts> for OneOrMany<Context> {
    fn from(contexts: Contexts) -> OneOrMany<Context> {
        match contexts {
            Contexts::One(context) => OneOrMany::One(context),
            Contexts::Many(contexts) => OneOrMany::Many(contexts),
        }
    }
}

impl TryFrom<String> for URI {
    type Error = Error;
    fn try_from(uri: String) -> Result<Self, Self::Error> {
        if uri.contains(":") {
            Ok(URI::String(uri))
        } else {
            Err(Error::URI)
        }
    }
}

impl From<URI> for String {
    fn from(uri: URI) -> String {
        let URI::String(string) = uri;
        string
    }
}

fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

fn jwt_encode(claims: &JWTClaims, keys: &JWTKeys) -> Result<String, Error> {
    let mut header = Header::default();
    let key: EncodingKey;
    if let Some(rs256_key) = &keys.rs256_private_key {
        header.alg = Algorithm::RS256;
        if let Some(ref key_id) = rs256_key.key_id {
            header.kid = Some(key_id.to_owned());
        }
        let der = rs256_key.to_der()?;
        key = EncodingKey::from_rsa_der(&der);
    } else if keys.es256k_private_key.is_some() {
        return Err(Error::AlgorithmNotImplemented);
    } else {
        return Err(Error::MissingKey);
    }
    Ok(jsonwebtoken::encode(&header, claims, &key)?)
}

impl Credential {
    pub fn from_json(s: &str) -> Result<Self, Error> {
        let vp: Self = serde_json::from_str(s)?;
        vp.validate()?;
        Ok(vp)
    }

    pub fn from_json_unsigned(s: &str) -> Result<Self, Error> {
        let vp: Self = serde_json::from_str(s)?;
        vp.validate_unsigned()?;
        Ok(vp)
    }

    pub fn from_jwt_keys(jwt: &String, keys: &JWTKeys) -> Result<Self, Error> {
        if let Some(rs256_key) = &keys.rs256_private_key {
            let validation = Validation::new(Algorithm::RS256);
            let rsa_params = match &rs256_key.params {
                Params::RSA(params) => params,
                _ => return Err(Error::MissingKeyParameters),
            };
            let modulus = match &rsa_params.modulus {
                Some(n) => n.0.clone(),
                None => return Err(Error::MissingKeyParameters),
            };
            let exponent = match &rsa_params.exponent {
                Some(n) => n.0.clone(),
                None => return Err(Error::MissingKeyParameters),
            };
            let modulus_b64 = base64::encode_config(modulus, base64::URL_SAFE_NO_PAD);
            let exponent_b64 = base64::encode_config(exponent, base64::URL_SAFE_NO_PAD);
            let key = DecodingKey::from_rsa_components(&modulus_b64, &exponent_b64);
            Credential::from_jwt(jwt, &key, &validation)
        } else if keys.es256k_private_key.is_some() {
            Err(Error::AlgorithmNotImplemented)
        } else {
            Err(Error::MissingKey)
        }
    }

    pub fn from_jwt(
        jwt: &String,
        key: &DecodingKey,
        validation: &Validation,
    ) -> Result<Self, Error> {
        let token_data = jsonwebtoken::decode::<JWTClaims>(jwt, &key, validation)?;
        Self::from_token_data(token_data)
    }

    pub fn from_jwt_unsigned(jwt: &String) -> Result<Self, Error> {
        let token_data = jsonwebtoken::dangerous_insecure_decode::<JWTClaims>(jwt)?;
        let vc = Self::from_token_data(token_data)?;
        vc.validate_unsigned()?;
        Ok(vc)
    }

    pub fn from_token_data(token_data: jsonwebtoken::TokenData<JWTClaims>) -> Result<Self, Error> {
        let mut vc = match token_data.claims.verifiable_credential {
            Some(vc) => vc,
            None => return Err(Error::MissingCredential),
        };
        if let Some(exp) = token_data.claims.expiration_time {
            vc.expiration_date = Utc.timestamp_opt(exp, 0).latest();
        }
        if let Some(iss) = token_data.claims.issuer {
            vc.issuer = Some(Issuer::URI(URI::String(iss)));
        }
        if let Some(nbf) = token_data.claims.not_before {
            if let Some(time) = Utc.timestamp_opt(nbf, 0).latest() {
                vc.issuance_date = Some(time);
            } else {
                return Err(Error::TimeError);
            }
        }
        if let Some(sub) = token_data.claims.subject {
            if let OneOrMany::One(ref mut subject) = vc.credential_subject {
                subject.id = Some(URI::String(sub));
            } else {
                return Err(Error::InvalidSubject);
            }
        }
        if let Some(id) = token_data.claims.jwt_id {
            let uri = URI::try_from(id)?;
            vc.id = Some(uri);
        }
        Ok(vc)
    }

    fn to_jwt_claims(&self, aud: &String) -> Result<JWTClaims, Error> {
        let subject = match self.credential_subject.to_single() {
            Some(subject) => subject,
            None => return Err(Error::InvalidSubject),
        };
        let subject_id: String = match subject.id.clone() {
            Some(id) => id.into(),
            // Credential subject must have id for JWT
            None => return Err(Error::InvalidSubject),
        };

        let mut vc = self.clone();
        // Remove fields from vc that are duplicated into the claims,
        // except for timestamps (in case of conversion discrepencies).
        Ok(JWTClaims {
            expiration_time: vc.expiration_date.map(|date| date.timestamp()),
            issuer: match vc.issuer.take() {
                Some(Issuer::URI(URI::String(uri))) => Some(uri),
                Some(Issuer::Object(_)) => return Err(Error::InvalidIssuer),
                None => None,
            },
            not_before: vc.issuance_date.map(|date| date.timestamp()),
            jwt_id: vc.id.take().map(|id| id.into()),
            subject: Some(subject_id),
            audience: Some(aud.clone()),
            verifiable_credential: Some(vc),
            verifiable_presentation: None,
        })
    }

    pub fn encode_jwt_unsigned(&self, aud: &String) -> Result<String, Error> {
        let claims = self.to_jwt_claims(aud)?;
        Ok([
            base64_encode_json(&Header::default())?.as_ref(),
            base64_encode_json(&claims)?.as_ref(),
            "",
        ]
        .join("."))
    }

    pub fn encode_sign_jwt(&self, keys: &JWTKeys, aud: &String) -> Result<String, Error> {
        let claims = self.to_jwt_claims(aud)?;
        jwt_encode(&claims, &keys)
    }

    pub fn validate_unsigned(&self) -> Result<(), Error> {
        if !self.type_.contains(&"VerifiableCredential".to_string()) {
            return Err(Error::MissingTypeVerifiableCredential);
        }
        if self.issuer.is_none() {
            return Err(Error::MissingIssuer);
        }
        if self.issuance_date.is_none() {
            return Err(Error::MissingIssuanceDate);
        }

        if self.is_zkp() {
            if self.credential_schema.is_none() {
                return Err(Error::MissingCredentialSchema);
            }
        }

        Ok(())
    }

    pub fn is_zkp(&self) -> bool {
        match &self.proof {
            Some(proofs) => {
                proofs.any(|proof| proof.type_.contains(&"CLSignature2019".to_string()))
            }
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.validate_unsigned()?;
        if self.proof.is_none() {
            return Err(Error::MissingProof);
        }

        Ok(())
    }
}

impl Presentation {
    pub fn from_json(s: &str) -> Result<Self, Error> {
        let vp: Self = serde_json::from_str(s)?;
        vp.validate()?;
        Ok(vp)
    }

    pub fn from_json_unsigned(s: &str) -> Result<Self, Error> {
        let vp: Self = serde_json::from_str(s)?;
        vp.validate_unsigned()?;
        Ok(vp)
    }

    pub fn encode_sign_jwt(&self, keys: &JWTKeys, aud: &String) -> Result<String, Error> {
        let claims = JWTClaims {
            expiration_time: None,
            not_before: None,
            subject: None,
            issuer: self.holder.clone().map(|id| id.into()),
            jwt_id: self.id.clone().map(|id| id.into()),
            audience: Some(aud.clone()),
            verifiable_credential: None,
            verifiable_presentation: Some(self.clone()),
        };
        jwt_encode(&claims, &keys)
    }

    pub fn validate_unsigned(&self) -> Result<(), Error> {
        if !self.type_.contains(&"VerifiablePresentation".to_string()) {
            return Err(Error::MissingTypeVerifiablePresentation);
        }

        // https://w3c.github.io/vc-data-model/#zero-knowledge-proofs
        // With ZKP, VC in VP must have credentialSchema
        let missing_zkp_credential_schema = self.verifiable_credential.any(|vc| match vc {
            CredentialOrJWT::Credential(vc) => {
                if vc.is_zkp() {
                    vc.credential_schema.is_none()
                } else {
                    false
                }
            }
            CredentialOrJWT::JWT(_) => {
                // TODO: check JWT-decoded VC
                // https://w3c.github.io/vc-data-model/#example-31-jwt-payload-of-a-jwt-based-verifiable-presentation-non-normative
                false
            }
        });
        if missing_zkp_credential_schema {
            return Err(Error::MissingCredentialSchema);
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.validate_unsigned()?;

        if self.proof.is_none() {
            return Err(Error::MissingProof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct Config {
        #[serde(rename = "jwt")]
        pub keys: JWTKeys,
        #[serde(flatten)]
        pub property_set: Option<Map<String, Value>>,
    }

    #[test]
    fn credential_from_json() {
        let doc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let id = "http://example.org/credentials/3731";
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let id1: String = doc.id.unwrap().into();
        assert_eq!(id1, id);
    }

    #[test]
    fn credential_multiple_contexts() {
        let doc_str = r###"{
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        if let Contexts::Many(contexts) = doc.context {
            assert_eq!(contexts.len(), 2);
        } else {
            assert!(false);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid context")]
    fn credential_invalid_context() {
        let doc_str = r###"{
            "@context": "https://example.org/invalid-context",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[test]
    fn encode_sign_jwt() {
        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/192783",
            "type": "VerifiableCredential",
            "issuer": "https://example.org/issuers/1345",
            "issuanceDate": "2020-08-25T11:26:53Z",
            "expirationDate": "2021-08-25T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:a6c78986cc36418b95a22d7f736",
                "spouse": "Example Person"
            }
        }"###;

        const CONFIG: &'static [u8] = include_bytes!("bin/ssi-vc-test/config.json");
        let conf: Config = serde_json::from_slice(CONFIG).unwrap();

        let vc: Credential = serde_json::from_str(vc_str).unwrap();
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let signed_jwt = vc.encode_sign_jwt(&conf.keys, &aud).unwrap();
        println!("{:?}", signed_jwt);
    }

    #[test]
    fn decode_verify_jwt() {
        const CONFIG: &'static [u8] = include_bytes!("bin/ssi-vc-test/config.json");
        let conf: Config = serde_json::from_slice(CONFIG).unwrap();

        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/192783",
            "type": "VerifiableCredential",
            "issuer": "https://example.org/issuers/1345",
            "issuanceDate": "2020-08-25T11:26:53Z",
            "expirationDate": "2021-08-25T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:a6c78986cc36418b95a22d7f736",
                "spouse": "Example Person"
            }
        }"###;

        let vc: Credential = serde_json::from_str(vc_str).unwrap();
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let signed_jwt = vc.encode_sign_jwt(&conf.keys, &aud).unwrap();

        let vc1 = Credential::from_jwt_keys(&signed_jwt, &conf.keys).unwrap();
        assert_eq!(vc.id, vc1.id);
    }
}
