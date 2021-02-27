use std::collections::HashMap as Map;
use std::convert::TryFrom;
use std::str::FromStr;

use crate::did::VerificationMethod;
use crate::did_resolve::{DIDResolver, ResolutionInputMetadata};
use crate::error::Error;
use crate::jsonld::{json_to_dataset, StaticLoader};
use crate::jwk::{JWTKeys, JWK};
use crate::ldp::{now_ms, LinkedDataDocument, LinkedDataProofs, ProofPreparation};
use crate::one_or_many::OneOrMany;
use crate::rdf::DataSet;

use async_trait::async_trait;
use chrono::prelude::*;
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
// - Decode JWT VC embedded in VP
// - Look up keys for verify from a set or store, or using verificationMethod
// - Fetch contexts, to support arbitrary VC and LD-Proof properties
// - Support normalization of arbitrary JSON-LD
// - Support more LD-proof types

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
    pub credential_subject: OneOrMany<CredentialSubject>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
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
pub struct CredentialSubject {
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

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "@context")]
    // TODO: use consistent types for context
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<ProofPurpose>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // Note: ld-proofs specifies verificationMethod as a "set of parameters",
    // but all examples use a single string.
    pub verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>, // ISO 8601
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
// #[serde(untagged)]
#[serde(rename_all = "camelCase")]
pub enum ProofPurpose {
    AssertionMethod,
    Authentication,
    KeyAgreement,
    ContractAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
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
    pub context: Contexts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<OneOrMany<CredentialOrJWT>>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
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

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
/// Options for specifying how the LinkedDataProof is created.
/// Reference: vc-http-api
pub struct LinkedDataProofOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The URI of the verificationMethod used for the proof. If omitted a default
    /// assertionMethod will be used.
    pub verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The purpose of the proof. If omitted "assertionMethod" will be used.
    pub proof_purpose: Option<ProofPurpose>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The date of the proof. If omitted system time will be used.
    pub created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The challenge of the proof.
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The domain of the proof.
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Checks to perform
    pub checks: Option<Vec<Check>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
pub enum Check {
    Proof,
}

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Object summarizing a verification
/// Reference: vc-http-api
pub struct VerificationResult {
    /// The checks performed
    pub checks: Vec<Check>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Errors
    pub errors: Vec<String>,
}

impl Default for ProofPurpose {
    fn default() -> Self {
        Self::AssertionMethod
    }
}

impl Default for LinkedDataProofOptions {
    fn default() -> Self {
        Self {
            verification_method: None,
            proof_purpose: Some(ProofPurpose::default()),
            created: Some(now_ms()),
            challenge: None,
            domain: None,
            checks: Some(vec![Check::Proof]),
        }
    }
}

impl VerificationResult {
    fn new() -> Self {
        Self {
            checks: vec![],
            warnings: vec![],
            errors: vec![],
        }
    }

    fn error(err: &str) -> Self {
        Self {
            checks: vec![],
            warnings: vec![],
            errors: vec![err.to_string()],
        }
    }

    fn append(&mut self, other: &mut Self) {
        self.checks.append(&mut other.checks);
        self.warnings.append(&mut other.warnings);
        self.errors.append(&mut other.errors);
    }
}

impl From<Result<(), Error>> for VerificationResult {
    fn from(res: Result<(), Error>) -> Self {
        Self {
            checks: vec![],
            warnings: vec![],
            errors: match res {
                Ok(_) => vec![],
                Err(error) => vec![error.to_string()],
            },
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
        if uri.contains(':') {
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

pub fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

fn jwt_encode(claims: &JWTClaims, keys: &JWTKeys) -> Result<String, Error> {
    let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
        rs256_key
    } else if let Some(es256k_key) = &keys.es256k_private_key {
        es256k_key
    } else {
        return Err(Error::MissingKey);
    };
    let algorithm = jwk.get_algorithm().ok_or(Error::MissingAlgorithm)?;
    Ok(crate::jwt::encode_sign(algorithm, claims, &jwk)?)
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

    pub fn from_jwt_keys(jwt: &str, keys: &JWTKeys) -> Result<Self, Error> {
        let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
            rs256_key
        } else if keys.es256k_private_key.is_some() {
            return Err(Error::AlgorithmNotImplemented);
        } else {
            return Err(Error::MissingKey);
        };
        Credential::from_jwt(jwt, &jwk)
    }

    pub fn from_jwt(jwt: &str, key: &JWK) -> Result<Self, Error> {
        let token_data: JWTClaims = crate::jwt::decode_verify(jwt, &key)?;
        Self::from_jwt_claims(token_data)
    }

    pub fn from_jwt_unsigned(jwt: &str) -> Result<Self, Error> {
        let token_data: JWTClaims = crate::jwt::decode_unverified(jwt)?;
        let vc = Self::from_jwt_claims(token_data)?;
        vc.validate_unsigned()?;
        Ok(vc)
    }

    pub(crate) fn from_jwt_unsigned_embedded(jwt: &str) -> Result<Self, Error> {
        let token_data: JWTClaims = crate::jwt::decode_unverified(jwt)?;
        let vc = Self::from_jwt_claims(token_data)?;
        vc.validate_unsigned_embedded()?;
        Ok(vc)
    }

    pub fn from_jwt_claims(claims: JWTClaims) -> Result<Self, Error> {
        let mut vc = match claims.verifiable_credential {
            Some(vc) => vc,
            None => return Err(Error::MissingCredential),
        };
        if let Some(exp) = claims.expiration_time {
            vc.expiration_date = Utc.timestamp_opt(exp, 0).latest();
        }
        if let Some(iss) = claims.issuer {
            vc.issuer = Some(Issuer::URI(URI::String(iss)));
        }
        if let Some(nbf) = claims.not_before {
            if let Some(time) = Utc.timestamp_opt(nbf, 0).latest() {
                vc.issuance_date = Some(time);
            } else {
                return Err(Error::TimeError);
            }
        }
        if let Some(sub) = claims.subject {
            if let OneOrMany::One(ref mut subject) = vc.credential_subject {
                subject.id = Some(URI::String(sub));
            } else {
                return Err(Error::InvalidSubject);
            }
        }
        if let Some(id) = claims.jwt_id {
            let uri = URI::try_from(id)?;
            vc.id = Some(uri);
        }
        Ok(vc)
    }

    fn to_jwt_claims(&self, aud: &str) -> Result<JWTClaims, Error> {
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
            audience: Some(aud.to_string()),
            verifiable_credential: Some(vc),
            verifiable_presentation: None,
        })
    }

    pub fn encode_jwt_unsigned(&self, aud: &str) -> Result<String, Error> {
        let claims = self.to_jwt_claims(aud)?;
        Ok(crate::jwt::encode_unsigned(&claims)?)
    }

    pub fn encode_sign_jwt(&self, keys: &JWTKeys, aud: &str) -> Result<String, Error> {
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

        if self.is_zkp() && self.credential_schema.is_none() {
            return Err(Error::MissingCredentialSchema);
        }

        Ok(())
    }

    pub(crate) fn validate_unsigned_embedded(&self) -> Result<(), Error> {
        self.validate_unsigned()?;

        // https://w3c.github.io/vc-data-model/#zero-knowledge-proofs
        // With ZKP, VC in VP must have credentialSchema
        if self.is_zkp() && self.credential_schema.is_none() {
            return Err(Error::MissingCredentialSchema);
        }

        Ok(())
    }

    pub fn is_zkp(&self) -> bool {
        match &self.proof {
            Some(proofs) => proofs
                .into_iter()
                .any(|proof| proof.type_.contains(&"CLSignature2019".to_string())),
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

    async fn filter_proofs(
        &self,
        options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
    ) -> Result<Vec<&Proof>, String> {
        // Allow any of issuer's verification methods by default
        let mut options = options.unwrap_or_default();
        let allowed_vms = match options.verification_method.take() {
            Some(vm) => vec![vm],
            None => {
                if let Some(ref issuer) = self.issuer {
                    let issuer_uri = match issuer.clone() {
                        Issuer::URI(uri) => uri,
                        Issuer::Object(object_with_id) => object_with_id.id,
                    };
                    let URI::String(issuer_did) = issuer_uri;
                    get_verification_methods(&issuer_did, resolver).await?
                } else {
                    Vec::new()
                }
            }
        };
        Ok(self
            .proof
            .iter()
            .flatten()
            .filter(|proof| proof.matches(&options, &allowed_vms))
            .collect())
    }

    // TODO: factor this out of VC and VP
    pub async fn verify(
        &self,
        options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
    ) -> VerificationResult {
        let proofs = match self.filter_proofs(options, resolver).await {
            Ok(proofs) => proofs,
            Err(err) => {
                return VerificationResult::error(&format!("Unable to filter proofs: {}", err));
            }
        };
        if proofs.is_empty() {
            return VerificationResult::error("No applicable proof");
            // TODO: say why, e.g. expired
        }
        let mut results = VerificationResult::new();
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof.verify(self, resolver).await;
            if result.errors.is_empty() {
                result.checks.push(Check::Proof);
                return result;
            };
            results.append(&mut result);
        }
        results
    }

    // https://w3c-ccg.github.io/ld-proofs/
    // https://w3c-ccg.github.io/lds-rsa2018/
    // https://w3c-ccg.github.io/vc-http-api/#/Issuer/issueCredential
    pub async fn generate_proof(
        &self,
        jwk: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, jwk).await
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<ProofPreparation, Error> {
        LinkedDataProofs::prepare(self, options, public_key).await
    }

    pub fn add_proof(&mut self, proof: Proof) {
        self.proof = match self.proof.take() {
            None => Some(OneOrMany::One(proof)),
            Some(OneOrMany::One(existing_proof)) => {
                Some(OneOrMany::Many(vec![existing_proof, proof]))
            }
            Some(OneOrMany::Many(mut proofs)) => {
                proofs.push(proof);
                Some(OneOrMany::Many(proofs))
            }
        }
    }
}

#[async_trait]
impl LinkedDataDocument for Credential {
    fn get_contexts(&self) -> Result<Option<String>, Error> {
        Ok(Some(serde_json::to_string(&self.context)?))
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
    ) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.proof = None;
        let json = serde_json::to_string(&copy)?;
        let more_contexts = match parent {
            Some(parent) => parent.get_contexts()?,
            None => None,
        };
        let mut loader = StaticLoader;
        json_to_dataset(&json, more_contexts.as_ref(), false, None, &mut loader).await
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

    pub fn encode_sign_jwt(&self, keys: &JWTKeys, aud: &str) -> Result<String, Error> {
        let claims = JWTClaims {
            expiration_time: None,
            not_before: None,
            subject: None,
            issuer: self.holder.clone().map(|id| id.into()),
            jwt_id: self.id.clone().map(|id| id.into()),
            audience: Some(aud.to_string()),
            verifiable_credential: None,
            verifiable_presentation: Some(self.clone()),
        };
        jwt_encode(&claims, &keys)
    }

    pub fn validate_unsigned(&self) -> Result<(), Error> {
        if !self.type_.contains(&"VerifiablePresentation".to_string()) {
            return Err(Error::MissingTypeVerifiablePresentation);
        }

        for ref vc in self.verifiable_credential.iter().flatten() {
            match vc {
                CredentialOrJWT::Credential(vc) => {
                    vc.validate_unsigned_embedded()?;
                }
                CredentialOrJWT::JWT(jwt) => {
                    // https://w3c.github.io/vc-data-model/#example-31-jwt-payload-of-a-jwt-based-verifiable-presentation-non-normative
                    Credential::from_jwt_unsigned_embedded(&jwt)?;
                }
            };
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

    pub async fn generate_proof(
        &self,
        jwk: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, jwk).await
    }

    pub fn add_proof(&mut self, proof: Proof) {
        self.proof = match self.proof.take() {
            None => Some(OneOrMany::One(proof)),
            Some(OneOrMany::One(existing_proof)) => {
                Some(OneOrMany::Many(vec![existing_proof, proof]))
            }
            Some(OneOrMany::Many(mut proofs)) => {
                proofs.push(proof);
                Some(OneOrMany::Many(proofs))
            }
        }
    }

    async fn filter_proofs(
        &self,
        options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
    ) -> Result<Vec<&Proof>, String> {
        // Allow any of holder's verification methods by default
        let mut options = options.unwrap_or_default();
        let allowed_vms = match options.verification_method.take() {
            Some(vm) => vec![vm],
            None => {
                if let Some(URI::String(ref holder)) = self.holder {
                    get_verification_methods(&holder, resolver).await?
                } else {
                    Vec::new()
                }
            }
        };
        Ok(self
            .proof
            .iter()
            .flatten()
            .filter(|proof| proof.matches(&options, &allowed_vms))
            .collect())
    }

    // TODO: factor this out of VC and VP
    pub async fn verify(
        &self,
        options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
    ) -> VerificationResult {
        let proofs = match self.filter_proofs(options, resolver).await {
            Ok(proofs) => proofs,
            Err(err) => {
                return VerificationResult::error(&format!("Unable to filter proofs: {}", err));
            }
        };
        if proofs.is_empty() {
            return VerificationResult::error("No applicable proof");
            // TODO: say why, e.g. expired
        }
        let mut results = VerificationResult::new();
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof.verify(self, resolver).await;
            if result.errors.is_empty() {
                result.checks.push(Check::Proof);
                return result;
            };
            results.append(&mut result);
        }
        results
    }
}

impl Default for Presentation {
    fn default() -> Self {
        Self {
            context: Contexts::Many(vec![Context::URI(URI::String(DEFAULT_CONTEXT.to_string()))]),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: None,
            id: None,
            proof: None,
            holder: None,
            property_set: None,
        }
    }
}

/// Get a DID's first verification method
pub async fn get_verification_method(did: &str, resolver: &dyn DIDResolver) -> Option<String> {
    let vms = get_verification_methods(did, resolver)
        .await
        .unwrap_or_default();
    vms.into_iter().next()
}

/// Resolve a DID and get its the verification methods from its DID document.
pub async fn get_verification_methods(
    did: &str,
    resolver: &dyn DIDResolver,
) -> Result<Vec<String>, String> {
    let (res_meta, doc_opt, _meta) = resolver
        .resolve(did, &ResolutionInputMetadata::default())
        .await;
    if let Some(err) = res_meta.error {
        return Err(err.to_string());
    }
    let doc = doc_opt.ok_or("Missing document".to_string())?;
    let vms = doc
        .verification_method
        .iter()
        .flatten()
        .map(|vm| match vm {
            VerificationMethod::Map(map) => map.id.to_owned(),
            VerificationMethod::DIDURL(didurl) => didurl.to_string(),
        })
        .collect();
    Ok(vms)
}

#[async_trait]
impl LinkedDataDocument for Presentation {
    fn get_contexts(&self) -> Result<Option<String>, Error> {
        Ok(Some(serde_json::to_string(&self.context)?))
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
    ) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.proof = None;
        let json = serde_json::to_string(&copy)?;
        let more_contexts = match parent {
            Some(parent) => parent.get_contexts()?,
            None => None,
        };
        let mut loader = StaticLoader;
        json_to_dataset(&json, more_contexts.as_ref(), false, None, &mut loader).await
    }
}

macro_rules! assert_local {
    ($cond:expr) => {
        if !$cond {
            return false;
        }
    };
}

impl Proof {
    pub fn new(type_: &str) -> Self {
        Self {
            type_: type_.to_string(),
            ..Default::default()
        }
    }

    pub fn matches(&self, options: &LinkedDataProofOptions, allowed_vms: &Vec<String>) -> bool {
        if let Some(ref verification_method) = options.verification_method {
            assert_local!(self.verification_method.as_ref() == Some(verification_method));
        }
        if let Some(vm) = self.verification_method.as_ref() {
            assert_local!(allowed_vms.contains(vm));
        }
        if let Some(created) = self.created {
            assert_local!(options.created.unwrap_or_else(now_ms) >= created);
        } else {
            return false;
        }
        if let Some(ref challenge) = options.challenge {
            assert_local!(self.challenge.as_ref() == Some(challenge));
        }
        if let Some(ref domain) = options.domain {
            assert_local!(self.domain.as_ref() == Some(domain));
        }
        if let Some(ref proof_purpose) = options.proof_purpose {
            assert_local!(self.proof_purpose.as_ref() == Some(proof_purpose));
        }
        true
    }

    pub async fn verify(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> VerificationResult {
        LinkedDataProofs::verify(self, document, resolver)
            .await
            .into()
    }
}

#[async_trait]
impl LinkedDataDocument for Proof {
    fn get_contexts(&self) -> Result<Option<String>, Error> {
        Ok(None)
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
    ) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.jws = None;
        copy.proof_value = None;
        let json = serde_json::to_string(&copy)?;
        let more_contexts = match parent {
            Some(parent) => parent.get_contexts()?,
            None => None,
        };
        let mut loader = StaticLoader;
        json_to_dataset(&json, more_contexts.as_ref(), false, None, &mut loader).await
    }
}

impl FromStr for ProofPurpose {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "contractAgreement" => Ok(Self::ContractAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            _ => Err(Error::UnsupportedProofPurpose),
        }
    }
}

impl TryFrom<String> for ProofPurpose {
    type Error = Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<ProofPurpose> for String {
    fn from(purpose: ProofPurpose) -> String {
        match purpose {
            ProofPurpose::Authentication => "authentication".to_string(),
            ProofPurpose::AssertionMethod => "assertionMethod".to_string(),
            ProofPurpose::KeyAgreement => "keyAgreement".to_string(),
            ProofPurpose::ContractAgreement => "contractAgreement".to_string(),
            ProofPurpose::CapabilityInvocation => "capabilityInvocation".to_string(),
            ProofPurpose::CapabilityDelegation => "capabilityDelegation".to_string(),
        }
    }
}

impl FromStr for Check {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "proof" => Ok(Self::Proof),
            _ => Err(Error::UnsupportedCheck),
        }
    }
}

impl TryFrom<String> for Check {
    type Error = Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<Check> for String {
    fn from(purpose: Check) -> String {
        match purpose {
            Check::Proof => "proof".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::example::DIDExample;
    use crate::urdna2015;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct Config {
        #[serde(rename = "jwt")]
        pub keys: JWTKeys,
        #[serde(flatten)]
        pub property_set: Option<Map<String, Value>>,
    }

    const JWK_JSON: &'static str = include_str!("../tests/rsa2048-2020-08-25.json");

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

        const CONFIG: &'static [u8] = include_bytes!("../vc-test/config.json");
        let conf: Config = serde_json::from_slice(CONFIG).unwrap();

        let vc: Credential = serde_json::from_str(vc_str).unwrap();
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let signed_jwt = vc.encode_sign_jwt(&conf.keys, &aud).unwrap();
        println!("{:?}", signed_jwt);
    }

    #[test]
    fn decode_verify_jwt() {
        const CONFIG: &'static [u8] = include_bytes!("../vc-test/config.json");
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

    #[async_std::test]
    async fn credential_prove_verify() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some("did:example:foo#key1".to_string());
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // mess with the proof to make verify fail
        match vc.proof {
            None => unreachable!(),
            Some(OneOrMany::Many(_)) => unreachable!(),
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                None => unreachable!(),
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
            },
        }
        println!("{}", serde_json::to_string_pretty(&vc).unwrap());
        let verification_result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.len() >= 1);
    }

    #[async_std::test]
    async fn credential_proof_preparation() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some("did:example:foo#key1".to_string());
        let algorithm = key.algorithm.unwrap();
        let public_key = key.to_public();
        let preparation = vc.prepare_proof(&public_key, &issue_options).await.unwrap();
        let signing_input = match preparation.signing_input {
            crate::ldp::SigningInput::Bytes(ref bytes) => bytes,
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected signing input type"),
        };
        let sig = crate::jws::sign_bytes(algorithm, &signing_input, &key).unwrap();
        let sig_b64 = base64::encode_config(sig, base64::URL_SAFE_NO_PAD);
        let proof = preparation.complete(&sig_b64).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // mess with the proof to make verify fail
        match vc.proof {
            None => unreachable!(),
            Some(OneOrMany::Many(_)) => unreachable!(),
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                None => unreachable!(),
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
            },
        }
        println!("{}", serde_json::to_string_pretty(&vc).unwrap());
        let verification_result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.len() >= 1);
    }

    #[async_std::test]
    async fn proof_json_to_urdna2015() {
        use serde_json::json;
        let proof_str = r###"{
            "type": "RsaSignature2018",
            "created": "2020-09-03T15:15:39Z",
            "creator": "https://example.org/foo/1",
            "proofPurpose": "assertionMethod"
        }"###;
        let urdna2015_expected = r###"_:c14n0 <http://purl.org/dc/terms/created> "2020-09-03T15:15:39Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://purl.org/dc/terms/creator> <https://example.org/foo/1> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#RsaSignature2018> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
"###;
        let proof: Proof = serde_json::from_str(proof_str).unwrap();
        struct ProofContexts(Value);
        #[async_trait]
        impl LinkedDataDocument for ProofContexts {
            fn get_contexts(&self) -> Result<Option<String>, Error> {
                Ok(Some(serde_json::to_string(&self.0)?))
            }

            async fn to_dataset_for_signing(
                &self,
                _parent: Option<&(dyn LinkedDataDocument + Sync)>,
            ) -> Result<DataSet, Error> {
                Err(Error::NotImplemented)
            }
        }
        let parent = ProofContexts(json!(["https://w3id.org/security/v1", DEFAULT_CONTEXT]));
        let proof_dataset = proof.to_dataset_for_signing(Some(&parent)).await.unwrap();
        let proof_dataset_normalized = urdna2015::normalize(&proof_dataset).unwrap();
        let proof_urdna2015 = proof_dataset_normalized.to_nquads().unwrap();
        eprintln!("proof:\n{}", proof_urdna2015);
        eprintln!("expected:\n{}", urdna2015_expected);
        assert_eq!(proof_urdna2015, urdna2015_expected);
    }

    #[async_std::test]
    async fn credential_json_to_urdna2015() {
        let credential_str = r#"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.com/credentials/4643",
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuers/14",
            "issuanceDate": "2018-02-24T05:28:04Z",
            "credentialSubject": {
                "id": "did:example:abcdef1234567",
                "name": "Jane Doe"
            }
        }"#;
        let urdna2015_expected = r#"<did:example:abcdef1234567> <http://schema.org/name> "Jane Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<http://example.com/credentials/4643> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.com/credentials/4643> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdef1234567> .
<http://example.com/credentials/4643> <https://www.w3.org/2018/credentials#issuanceDate> "2018-02-24T05:28:04Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.com/credentials/4643> <https://www.w3.org/2018/credentials#issuer> <https://example.com/issuers/14> .
"#;
        let vc: Credential = serde_json::from_str(credential_str).unwrap();
        let credential_dataset = vc.to_dataset_for_signing(None).await.unwrap();
        let credential_dataset_normalized = urdna2015::normalize(&credential_dataset).unwrap();
        let credential_urdna2015 = credential_dataset_normalized.to_nquads().unwrap();
        eprintln!("credential:\n{}", credential_urdna2015);
        eprintln!("expected:\n{}", urdna2015_expected);
        assert_eq!(credential_urdna2015, urdna2015_expected);
    }

    #[async_std::test]
    async fn credential_verify() {
        let vc_str = include_str!("../examples/vc.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[async_std::test]
    async fn cannot_add_properties_after_signing() {
        use serde_json::json;
        let vc_str = include_str!("../examples/vc.jsonld");
        let mut vc: Value = serde_json::from_str(vc_str).unwrap();
        vc["newProp"] = json!("foo");
        let vc: Credential = serde_json::from_value(vc).unwrap();
        let result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", result);
        assert!(!result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[async_std::test]
    async fn presentation_verify() {
        let vp_str = include_str!("../examples/vp.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();
        let mut verify_options = LinkedDataProofOptions::default();
        verify_options.proof_purpose = Some(ProofPurpose::Authentication);
        let result = vp.verify(Some(verify_options), &DIDExample).await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[async_std::test]
    async fn presentation_from_credential_issue_verify() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:placeholder",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        // Issue credential
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
        let mut vc_issue_options = LinkedDataProofOptions::default();
        let vc_issuer_key = "did:example:foo".to_string();
        let vc_issuer_vm = "did:example:foo#key1".to_string();
        vc.issuer = Some(Issuer::URI(URI::String(vc_issuer_key.to_string())));
        vc_issue_options.verification_method = Some(vc_issuer_vm);
        let vc_proof = vc.generate_proof(&key, &vc_issue_options).await.unwrap();
        vc.add_proof(vc_proof);
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        vc.validate().unwrap();
        let vc_verification_result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", vc_verification_result);
        assert!(vc_verification_result.errors.is_empty());

        // Issue Presentation with Credential
        let mut vp = Presentation {
            context: Contexts::Many(vec![Context::URI(URI::String(DEFAULT_CONTEXT.to_string()))]),
            id: Some(URI::String(
                "http://example.org/presentations/3731".to_string(),
            )),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        let vp_issuer_key = "did:example:foo#key1".to_string();
        vp.holder = Some(URI::String(vp_issuer_key.to_string()));
        vp_issue_options.verification_method = Some(vp_issuer_key);
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        let vp_proof = vp.generate_proof(&key, &vp_issue_options).await.unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDExample).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        let mut vp1 = vp.clone();
        match vp1.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp1.verify(Some(vp_issue_options), &DIDExample).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDExample).await.errors.len() > 0);
    }
}
