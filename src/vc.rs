use std::collections::HashMap as Map;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::str::FromStr;

use crate::error::Error;
use crate::jwk::{JWTKeys, JWK};
use crate::ldp::{LinkedDataDocument, LinkedDataProofs};
use crate::one_or_many::OneOrMany;
use crate::rdf::{
    BlankNodeLabel, DataSet, IRIRef, Literal, Object, Predicate, Statement, StringLiteral, Subject,
};

use chrono::prelude::*;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
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
    // name and identifier for example/testing purposes:
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<HTML>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
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
    pub expires: Option<DateTime<Utc>>, // ISO 8601
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum HTML {
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

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
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
}

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Object summarizing a verification
/// Reference: vc-http-api
pub struct VerificationResult {
    /// The checks performed
    pub checks: Vec<String>,
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
            created: Some(Utc::now()),
            challenge: None,
            domain: None,
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

impl From<HTML> for Literal {
    fn from(html: HTML) -> Self {
        let HTML::String(string) = html;
        Literal::Typed {
            string: StringLiteral(string),
            type_: IRIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML".to_string()),
        }
    }
}

impl From<URI> for IRIRef {
    fn from(uri: URI) -> Self {
        let URI::String(string) = uri;
        IRIRef(string)
    }
}

pub fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

fn jwt_encode(claims: &JWTClaims, keys: &JWTKeys) -> Result<String, Error> {
    let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
        rs256_key
    } else if keys.es256k_private_key.is_some() {
        return Err(Error::AlgorithmNotImplemented);
    } else {
        return Err(Error::MissingKey);
    };
    let header = jwk.to_jwt_header()?;
    let key = EncodingKey::try_from(jwk)?;
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

    pub fn from_jwt_keys(jwt: &str, keys: &JWTKeys) -> Result<Self, Error> {
        let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
            rs256_key
        } else if keys.es256k_private_key.is_some() {
            return Err(Error::AlgorithmNotImplemented);
        } else {
            return Err(Error::MissingKey);
        };
        let key = DecodingKey::try_from(jwk)?;
        let validation = Validation::try_from(jwk)?;
        Credential::from_jwt(jwt, &key, &validation)
    }

    pub fn from_jwt(jwt: &str, key: &DecodingKey, validation: &Validation) -> Result<Self, Error> {
        let token_data = jsonwebtoken::decode::<JWTClaims>(jwt, &key, validation)?;
        Self::from_token_data(token_data)
    }

    pub fn from_jwt_unsigned(jwt: &str) -> Result<Self, Error> {
        let token_data = jsonwebtoken::dangerous_insecure_decode::<JWTClaims>(jwt)?;
        let vc = Self::from_token_data(token_data)?;
        vc.validate_unsigned()?;
        Ok(vc)
    }

    pub(crate) fn from_jwt_unsigned_embedded(jwt: &String) -> Result<Self, Error> {
        let token_data = jsonwebtoken::dangerous_insecure_decode::<JWTClaims>(jwt)?;
        let vc = Self::from_token_data(token_data)?;
        vc.validate_unsigned_embedded()?;
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
        Ok([
            base64_encode_json(&Header::default())?.as_ref(),
            base64_encode_json(&claims)?.as_ref(),
            "",
        ]
        .join("."))
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

        if self.is_zkp() {
            if self.credential_schema.is_none() {
                return Err(Error::MissingCredentialSchema);
            }
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

    fn filter_proofs(&self, options: Option<LinkedDataProofOptions>) -> Vec<&Proof> {
        let options = options.unwrap_or_default();
        self.proof
            .iter()
            .flatten()
            .filter(|proof| proof.matches(&options))
            .collect()
    }

    pub fn verify(&self, options: Option<LinkedDataProofOptions>) -> VerificationResult {
        let proofs = self.filter_proofs(options);
        if proofs.is_empty() {
            return VerificationResult::error("No applicable proof");
            // TODO: say why, e.g. expired
        }
        let mut results = VerificationResult::new();
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof.verify(self);
            if result.errors.is_empty() {
                result.checks.push("Verified credential proof".to_string());
                return result;
            };
            results.append(&mut result);
        }
        results
    }

    // https://w3c-ccg.github.io/ld-proofs/
    // https://w3c-ccg.github.io/lds-rsa2018/
    // https://w3c-ccg.github.io/vc-http-api/#/Issuer/issueCredential
    pub fn generate_proof(
        &self,
        jwk: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, jwk)
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

impl LinkedDataDocument for Credential {
    fn to_dataset_for_signing(&self) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.proof = None;
        DataSet::try_from(copy)
    }
}

impl TryFrom<CredentialSubject> for DataSet {
    type Error = Error;
    fn try_from(credential_subject: CredentialSubject) -> Result<Self, Self::Error> {
        let mut statements: Vec<Statement> = Vec::new();

        if has_more_props(credential_subject.property_set) {
            return Err(Error::UnsupportedProperty);
        }

        let subject = match credential_subject.id {
            Some(id) => Subject::IRIRef(IRIRef::from(id)),
            None => Subject::BlankNodeLabel(BlankNodeLabel("_:c14n0".to_string())),
        };

        if let Some(name) = credential_subject.name {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef("http://schema.org/name".to_string())),
                object: Object::Literal(Literal::from(name)),
                graph_label: None,
            });
        }

        if let Some(identifier) = credential_subject.identifier {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef("http://schema.org/identifier".to_string())),
                object: Object::Literal(Literal::String {
                    string: StringLiteral(identifier),
                }),
                graph_label: None,
            });
        }

        Ok(DataSet {
            statements: statements,
        })
    }
}

fn has_more_props(property_set: Option<Map<String, Value>>) -> bool {
    match property_set {
        None => false,
        Some(ref props) => !props.is_empty(),
    }
}

impl<T> TryFrom<OneOrMany<T>> for DataSet
where
    DataSet: TryFrom<T>,
    <DataSet as TryFrom<T>>::Error: Into<Error>,
{
    type Error = Error;
    fn try_from(item: OneOrMany<T>) -> Result<Self, Self::Error> {
        match item {
            OneOrMany::One(value) => value.try_into().map_err(Into::into),
            OneOrMany::Many(values) => {
                let mut dataset = DataSet {
                    statements: Vec::new(),
                };
                for value in values {
                    let mut this_dataset: DataSet = value.try_into().map_err(Into::into)?;
                    dataset.statements.append(&mut this_dataset.statements);
                }
                Ok(dataset)
            }
        }
    }
}

impl TryFrom<Credential> for DataSet {
    type Error = Error;
    fn try_from(vc: Credential) -> Result<Self, Self::Error> {
        let mut statements: Vec<Statement> = Vec::new();
        let mut used_blank_node = false;

        let subject = match vc.id {
            Some(id) => Subject::IRIRef(IRIRef::from(id)),
            None => {
                used_blank_node = true;
                Subject::BlankNodeLabel(BlankNodeLabel("_:c14n0".to_string()))
            }
        };

        for vc_subject in vc.credential_subject {
            let vc_subject_id = match vc_subject.id.clone() {
                Some(id) => Object::IRIRef(IRIRef::from(id)),
                None => {
                    if used_blank_node {
                        return Err(Error::TooManyBlankNodes);
                    }
                    used_blank_node = true;
                    Object::BlankNodeLabel(BlankNodeLabel("_:c14n0".to_string()))
                }
            };
            let mut vc_subject_dataset: DataSet = vc_subject.try_into()?;
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://www.w3.org/2018/credentials#credentialSubject".to_string(),
                )),
                object: vc_subject_id,
                graph_label: None,
            });
            statements.append(&mut vc_subject_dataset.statements);
        }

        for type_ in vc.type_ {
            if type_ != "VerifiableCredential" {
                return Err(Error::UnsupportedType);
            }
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
                )),
                object: Object::IRIRef(IRIRef(
                    "https://www.w3.org/2018/credentials#".to_string() + &type_,
                )),
                graph_label: None,
            });
        }

        if let Some(issuance_date) = vc.issuance_date {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://www.w3.org/2018/credentials#issuanceDate".to_string(),
                )),
                object: Object::Literal(Literal::from(issuance_date)),
                graph_label: None,
            });
        }

        if let Some(issuer) = vc.issuer {
            let issuer_id = match issuer {
                Issuer::URI(uri) => uri,
                Issuer::Object(object_with_id) => {
                    if has_more_props(object_with_id.property_set) {
                        return Err(Error::UnsupportedProperty);
                    }
                    object_with_id.id
                }
            };
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://www.w3.org/2018/credentials#issuer".to_string(),
                )),
                object: Object::IRIRef(IRIRef::from(issuer_id)),
                graph_label: None,
            });
        }

        Ok(DataSet {
            statements: statements,
        })
    }
}

impl TryFrom<Proof> for DataSet {
    type Error = Error;
    fn try_from(proof: Proof) -> Result<Self, Self::Error> {
        let mut statements: Vec<Statement> = Vec::new();

        let subject = Subject::BlankNodeLabel(BlankNodeLabel("_:c14n0".to_string()));
        // TODO: use references instead of clones

        if let Some(created) = proof.created {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "http://purl.org/dc/terms/created".to_string(),
                )),
                object: Object::Literal(Literal::from(created)),
                graph_label: None,
            });
        }

        if let Some(creator) = proof.creator {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "http://purl.org/dc/terms/creator".to_string(),
                )),
                object: Object::IRIRef(IRIRef(creator)),
                graph_label: None,
            });
        }

        statements.push(Statement {
            subject: subject.clone(),
            predicate: Predicate::IRIRef(IRIRef(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
            )),
            object: Object::IRIRef(IRIRef(
                "https://w3id.org/security#".to_string() + &proof.type_,
            )),
            graph_label: None,
        });

        if let Some(challenge) = proof.challenge {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://w3id.org/security#challenge".to_string(),
                )),
                object: Object::Literal(Literal::String {
                    string: StringLiteral(challenge),
                }),
                graph_label: None,
            });
        }

        if let Some(domain) = proof.domain {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://w3id.org/security#domain".to_string(),
                )),
                object: Object::Literal(Literal::String {
                    string: StringLiteral(domain),
                }),
                graph_label: None,
            });
        }

        if let Some(expires) = proof.expires {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://w3id.org/security#expires".to_string(),
                )),
                object: Object::Literal(Literal::from(expires)),
                graph_label: None,
            });
        }

        if let Some(nonce) = proof.nonce {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef("https://w3id.org/security#nonce".to_string())),
                object: Object::Literal(Literal::String {
                    string: StringLiteral(nonce),
                }),
                graph_label: None,
            });
        }

        if let Some(purpose) = proof.proof_purpose {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://w3id.org/security#proofPurpose".to_string(),
                )),
                object: Object::IRIRef(IRIRef(
                    "https://w3id.org/security#".to_string() + &String::from(purpose),
                )),
                graph_label: None,
            });
        }

        if let Some(verification_method) = proof.verification_method {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://w3id.org/security#verificationMethod".to_string(),
                )),
                object: Object::IRIRef(IRIRef(verification_method)),
                graph_label: None,
            });
        }

        Ok(DataSet {
            statements: statements,
        })
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

        for ref vc in &self.verifiable_credential {
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

    pub fn generate_proof(
        &self,
        jwk: &JWK,
        options: &LinkedDataProofOptions,
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, jwk)
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

    fn filter_proofs(&self, options: Option<LinkedDataProofOptions>) -> Vec<&Proof> {
        let options = options.unwrap_or_default();
        self.proof
            .iter()
            .flatten()
            .filter(|proof| proof.matches(&options))
            .collect()
    }

    pub fn verify(&self, options: Option<LinkedDataProofOptions>) -> VerificationResult {
        let proofs = self.filter_proofs(options);
        if proofs.is_empty() {
            return VerificationResult::error("No applicable proof");
            // TODO: say why, e.g. expired
        }
        let mut results = VerificationResult::new();
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof.verify(self);
            if result.errors.is_empty() {
                result
                    .checks
                    .push("Verified presentation proof".to_string());
                return result;
            };
            results.append(&mut result);
        }
        results
    }
}

impl LinkedDataDocument for Presentation {
    fn to_dataset_for_signing(&self) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.proof = None;
        DataSet::try_from(copy)
    }
}

impl TryFrom<Presentation> for DataSet {
    type Error = Error;
    fn try_from(vp: Presentation) -> Result<Self, Self::Error> {
        let mut statements: Vec<Statement> = Vec::new();

        let subject = match vp.id {
            Some(id) => Subject::IRIRef(IRIRef::from(id)),
            None => return Err(Error::TooManyBlankNodes),
        };

        for type_ in vp.type_ {
            if type_ != "VerifiablePresentation" {
                return Err(Error::UnsupportedType);
            }
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
                )),
                object: Object::IRIRef(IRIRef(
                    "https://www.w3.org/2018/credentials#".to_string() + &type_,
                )),
                graph_label: None,
            });
        }

        if let Some(holder) = vp.holder {
            statements.push(Statement {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "https://www.w3.org/2018/credentials#holder".to_string(),
                )),
                object: Object::IRIRef(IRIRef::from(holder)),
                graph_label: None,
            });
        }

        for vc_or_jwt in vp.verifiable_credential {
            let vc = match vc_or_jwt {
                CredentialOrJWT::Credential(vc) => vc,
                CredentialOrJWT::JWT(_) => {
                    return Err(Error::JWTCredentialInPresentation);
                }
            };
            let mut vc_dataset = DataSet::try_from(vc)?;
            statements.append(&mut vc_dataset.statements);
        }

        Ok(DataSet {
            statements: statements,
        })
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
    pub fn matches(&self, options: &LinkedDataProofOptions) -> bool {
        if let Some(expires) = self.expires {
            assert_local!(Utc::now() < expires);
        }
        if let Some(ref verification_method) = options.verification_method {
            assert_local!(self.verification_method.as_ref() == Some(verification_method));
        }
        if let Some(created) = self.created {
            assert_local!(options.created.unwrap_or(Utc::now()) >= created);
        } else {
            return false;
        }
        if let Some(ref challenge) = options.challenge {
            assert_local!(self.challenge.as_ref() == Some(challenge));
        }
        if let Some(ref domain) = options.domain {
            assert_local!(self.domain.as_ref() == Some(domain));
        }
        let proof_purpose = options.proof_purpose.clone().unwrap_or_default();
        assert_local!(self.proof_purpose == Some(proof_purpose));
        true
    }

    pub fn verify(&self, document: &dyn LinkedDataDocument) -> VerificationResult {
        LinkedDataProofs::verify(self, document).into()
    }
}

impl LinkedDataDocument for Proof {
    fn to_dataset_for_signing(&self) -> Result<DataSet, Error> {
        let mut copy = self.clone();
        copy.jws = None;
        DataSet::try_from(copy)
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

    #[test]
    fn credential_prove_verify() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let mut issue_options = LinkedDataProofOptions::default();
        let issuer_key = "did:example:jwk:".to_string() + JWK_JSON;
        issue_options.verification_method = Some(issuer_key);
        let proof = vc.generate_proof(&key, &issue_options).unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None);
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
        let verification_result = vc.verify(None);
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.len() >= 1);
    }

    #[test]
    fn credential_prove_verify_did_key() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        // let key = JWK::generate_ed25519().unwrap();
        let key_json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww\",\"d\":\"39Ev8-k-jkKunJyFWog3k0OwgPjnKv_qwLhfqXdAXTY\"}";
        let key: JWK = serde_json::from_str(&key_json).unwrap();
        let did = key.to_did().unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(did);
        let proof = vc.generate_proof(&key, &issue_options).unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None);
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[test]
    fn proof_json_to_urdna2015() {
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
        let proof_dataset = proof.to_dataset_for_signing().unwrap();
        let proof_urdna2015 = proof_dataset.to_nquads().unwrap();
        assert_eq!(proof_urdna2015, urdna2015_expected);
    }

    #[test]
    fn credential_json_to_urdna2015() {
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
                "name": "Jane Doe",
                "identifier": "EXAMPLE_ID"
            }
        }"#;
        let urdna2015_expected = r#"<did:example:abcdef1234567> <http://schema.org/identifier> "EXAMPLE_ID" .
<did:example:abcdef1234567> <http://schema.org/name> "Jane Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<http://example.com/credentials/4643> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.com/credentials/4643> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdef1234567> .
<http://example.com/credentials/4643> <https://www.w3.org/2018/credentials#issuanceDate> "2018-02-24T05:28:04Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.com/credentials/4643> <https://www.w3.org/2018/credentials#issuer> <https://example.com/issuers/14> .
"#;
        let vc: Credential = serde_json::from_str(credential_str).unwrap();
        let credential_dataset = vc.to_dataset_for_signing().unwrap();
        let credential_urdna2015 = credential_dataset.to_nquads().unwrap();
        assert_eq!(credential_urdna2015, urdna2015_expected);
    }

    #[test]
    fn presentation_from_credential_issue_verify() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        // Issue credential
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
        let mut vc_issue_options = LinkedDataProofOptions::default();
        let vp_issuer_key = "did:example:jwk:".to_string() + JWK_JSON;
        vc_issue_options.verification_method = Some(vp_issuer_key);
        let vc_proof = vc.generate_proof(&key, &vc_issue_options).unwrap();
        vc.add_proof(vc_proof);
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        vc.validate().unwrap();
        let vc_verification_result = vc.verify(None);
        println!("{:#?}", vc_verification_result);
        assert!(vc_verification_result.errors.is_empty());

        // Issue Presentation with Credential
        let mut vp = Presentation {
            context: vec![DEFAULT_CONTEXT.to_string()],
            id: Some(URI::String(
                "http://example.org/presentations/3731".to_string(),
            )),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: OneOrMany::One(CredentialOrJWT::Credential(vc)),
            proof: None,
            holder: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        let vp_issuer_key = "did:example:jwk:".to_string() + JWK_JSON;
        vp_issue_options.verification_method = Some(vp_issuer_key);
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        let vp_proof = vp.generate_proof(&key, &vp_issue_options).unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()));
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        match vp.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp.verify(Some(vp_issue_options));
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);
    }
}
