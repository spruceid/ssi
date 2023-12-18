use std::collections::HashMap as Map;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

pub mod error;
pub use error::Error;
mod cacao;
pub mod revocation;

use cacao::BindingDelegation;
use serde_with::{formats::PreferMany, serde_as, OneOrMany as SerdeWithOneOrMany};
pub use ssi_core::{one_or_many::OneOrMany, uri::URI};
use ssi_dids::did_resolve::{resolve_key, DIDResolver};
pub use ssi_dids::VerificationRelationship as ProofPurpose;
use ssi_json_ld::parse_ld_context;
use ssi_json_ld::{json_to_dataset, rdf::DataSet, ContextLoader};
use ssi_jwk::{JWTKeys, JWK};
use ssi_jws::Header;
pub use ssi_jwt::NumericDate;
use ssi_ldp::{
    assert_local, Check, Error as LdpError, LinkedDataDocument, LinkedDataProofs, Proof,
    ProofPreparation,
};
pub use ssi_ldp::{Context, LinkedDataProofOptions, VerificationResult};

use async_trait::async_trait;
use chrono::{prelude::*, LocalResult};
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
pub const DEFAULT_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

// work around https://github.com/w3c/vc-test-suite/issues/103
pub const ALT_DEFAULT_CONTEXT: &str = "https://w3.org/2018/credentials/v1";

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<StringOrURI>,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,
    pub credential_subject: OneOrMany<CredentialSubject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Issuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<VCDateTime>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<VCDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(deserialize_as = "Option<SerdeWithOneOrMany<_, PreferMany>>")]
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

/// RFC3339 date-time as used in VC Data Model
/// <https://www.w3.org/TR/vc-data-model/#issuance-date>
/// <https://www.w3.org/TR/vc-data-model/#expiration>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct VCDateTime {
    /// The date-time
    date_time: DateTime<FixedOffset>,
    /// Whether to use "Z" or "+00:00" when formatting the date-time in UTC
    use_z: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<Context>")]
pub enum Contexts {
    One(Context),
    Many(Vec<Context>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl CredentialSubject {
    /// Check if the credential subject is empty
    ///
    /// An empty credential subject (containing no properties, not even an id property) is
    /// considered invalid, as the VC Data Model defines the value of the
    /// [credentialSubject](https://www.w3.org/TR/vc-data-model/#credential-subject) property as
    /// "a set of objects that contain one or more properties [...]"
    pub fn is_empty(&self) -> bool {
        self.id.is_none()
            && match self.property_set {
                Some(ref ps) => ps.is_empty(),
                None => true,
            }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Issuer {
    URI(URI),
    Object(ObjectWithId),
}

impl Issuer {
    /// Return this issuer's id URI
    pub fn get_id(&self) -> String {
        match self {
            Self::URI(uri) => uri.to_string(),
            Self::Object(object_with_id) => object_with_id.id.to_string(),
        }
    }
    pub fn get_id_ref(&self) -> &str {
        match self {
            Self::URI(uri) => uri.as_str(),
            Self::Object(object_with_id) => object_with_id.id.as_str(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWithId {
    pub id: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum CheckableStatus {
    RevocationList2020Status(revocation::RevocationList2020Status),
    StatusList2021Entry(revocation::StatusList2021Entry),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CredentialStatus: Sync {
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<StringOrURI>,
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
    pub holder_binding: Option<OneOrMany<HolderBinding>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum HolderBinding {
    #[cfg(test)]
    ExampleHolderBinding2022 {
        to: URI,
        from: String,
        // proof: String,
    },
    #[serde(rename_all = "camelCase")]
    CacaoDelegationHolderBinding2022 { cacao_delegation: BindingDelegation },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum CredentialOrJWT {
    Credential(Credential),
    JWT(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
#[serde(try_from = "String")]
pub enum StringOrURI {
    String(String),
    URI(URI),
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[non_exhaustive]
pub struct JWTClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exp")]
    pub expiration_time: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iat")]
    pub issuance_date: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "iss")]
    pub issuer: Option<StringOrURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "nbf")]
    pub not_before: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sub")]
    pub subject: Option<StringOrURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "aud")]
    pub audience: Option<OneOrMany<StringOrURI>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vc")]
    pub verifiable_credential: Option<Credential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vp")]
    pub verifiable_presentation: Option<Presentation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl TryFrom<OneOrMany<Context>> for Contexts {
    type Error = LdpError;
    fn try_from(context: OneOrMany<Context>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err(LdpError::MissingContext),
            Some(Context::URI(URI::String(uri))) => uri,
            Some(Context::Object(_)) => return Err(LdpError::InvalidContext),
        };
        if ![DEFAULT_CONTEXT, DEFAULT_CONTEXT_V2, ALT_DEFAULT_CONTEXT].contains(&first_uri.as_str())
        {
            return Err(LdpError::InvalidContext);
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

impl Contexts {
    /// Check if the contexts contains the given URI.
    pub fn contains_uri(&self, uri: &str) -> bool {
        match self {
            Self::One(context) => {
                if let Context::URI(URI::String(context_uri)) = context {
                    if context_uri == uri {
                        return true;
                    }
                }
            }
            Self::Many(contexts) => {
                for context in contexts {
                    if let Context::URI(URI::String(context_uri)) = context {
                        if context_uri == uri {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

impl TryFrom<String> for StringOrURI {
    type Error = Error;
    fn try_from(string: String) -> Result<Self, Self::Error> {
        if string.contains(':') {
            let uri = URI::try_from(string)?;
            Ok(Self::URI(uri))
        } else {
            Ok(Self::String(string))
        }
    }
}
impl TryFrom<&str> for StringOrURI {
    type Error = Error;
    fn try_from(string: &str) -> Result<Self, Self::Error> {
        string.to_string().try_into()
    }
}

impl From<URI> for StringOrURI {
    fn from(uri: URI) -> Self {
        StringOrURI::URI(uri)
    }
}

impl From<StringOrURI> for String {
    fn from(id: StringOrURI) -> Self {
        match id {
            StringOrURI::URI(uri) => uri.into(),
            StringOrURI::String(s) => s,
        }
    }
}

impl StringOrURI {
    fn as_str(&self) -> &str {
        match self {
            StringOrURI::URI(URI::String(string)) => string.as_str(),
            StringOrURI::String(string) => string.as_str(),
        }
    }
}

impl FromStr for VCDateTime {
    type Err = chrono::format::ParseError;
    fn from_str(date_time: &str) -> Result<Self, Self::Err> {
        let use_z = date_time.ends_with('Z');
        let date_time = DateTime::parse_from_rfc3339(date_time)?;
        Ok(VCDateTime { date_time, use_z })
    }
}

impl TryFrom<String> for VCDateTime {
    type Error = chrono::format::ParseError;
    fn try_from(date_time: String) -> Result<Self, Self::Error> {
        Self::from_str(&date_time)
    }
}

impl From<VCDateTime> for String {
    fn from(z_date_time: VCDateTime) -> String {
        let VCDateTime { date_time, use_z } = z_date_time;
        date_time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, use_z)
    }
}

impl<Tz: chrono::TimeZone> From<DateTime<Tz>> for VCDateTime
where
    chrono::DateTime<chrono::FixedOffset>: From<chrono::DateTime<Tz>>,
{
    fn from(date_time: DateTime<Tz>) -> Self {
        Self {
            date_time: date_time.into(),
            use_z: true,
        }
    }
}

impl<Tz: chrono::TimeZone> From<VCDateTime> for DateTime<Tz>
where
    chrono::DateTime<Tz>: From<chrono::DateTime<chrono::FixedOffset>>,
{
    fn from(vc_date_time: VCDateTime) -> Self {
        Self::from(vc_date_time.date_time)
    }
}

pub fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

#[deprecated = "deprecated in favor of Credential::generate_jwt and Presentation::generate_jwt"]
fn jwt_encode(claims: &JWTClaims, keys: &JWTKeys) -> Result<String, Error> {
    let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
        rs256_key
    } else if let Some(es256k_key) = &keys.es256k_private_key {
        es256k_key
    } else {
        return Err(Error::LDP(LdpError::MissingKey));
    };
    let algorithm = jwk
        .get_algorithm()
        .ok_or(Error::LDP(LdpError::MissingAlgorithm))?;
    Ok(ssi_jwt::encode_sign(algorithm, claims, jwk)?)
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

    #[deprecated(note = "Use decode_verify_jwt")]
    pub fn from_jwt_keys(jwt: &str, keys: &JWTKeys) -> Result<Self, Error> {
        let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
            rs256_key
        } else if keys.es256k_private_key.is_some() {
            return Err(Error::JWS(ssi_jws::Error::AlgorithmNotImplemented));
        } else {
            return Err(Error::LDP(LdpError::MissingKey));
        };
        Credential::from_jwt(jwt, jwk)
    }

    pub fn from_jwt(jwt: &str, key: &JWK) -> Result<Self, Error> {
        let token_data: JWTClaims = ssi_jwt::decode_verify(jwt, key)?;
        Self::from_jwt_claims(token_data)
    }

    pub fn from_jwt_unsigned(jwt: &str) -> Result<Self, Error> {
        let token_data: JWTClaims = ssi_jwt::decode_unverified(jwt)?;
        let vc = Self::from_jwt_claims(token_data)?;
        vc.validate_unsigned()?;
        Ok(vc)
    }

    pub(crate) fn from_jwt_unsigned_embedded(jwt: &str) -> Result<Self, Error> {
        let token_data: JWTClaims = ssi_jwt::decode_unverified(jwt)?;
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
            let exp_date_time: LocalResult<DateTime<Utc>> = exp.into();
            vc.expiration_date = exp_date_time.latest().map(|time| VCDateTime {
                date_time: time.into(),
                use_z: true,
            });
        }
        if let Some(iss) = claims.issuer {
            if let StringOrURI::URI(issuer_uri) = iss {
                if let Some(Issuer::Object(ref mut issuer)) = vc.issuer {
                    issuer.id = issuer_uri;
                } else {
                    vc.issuer = Some(Issuer::URI(issuer_uri));
                }
            } else {
                return Err(Error::InvalidIssuer);
            }
        }
        if let Some(iat) = claims.issuance_date {
            let iat_date_time: LocalResult<DateTime<Utc>> = iat.into();
            if let Some(time) = iat_date_time.latest() {
                vc.issuance_date = Some(VCDateTime {
                    date_time: time.into(),
                    use_z: true,
                })
            }
        } else if let Some(nbf) = claims.not_before {
            let nbf_date_time: LocalResult<DateTime<Utc>> = nbf.into();
            if let Some(time) = nbf_date_time.latest() {
                vc.issuance_date = Some(VCDateTime {
                    date_time: time.into(),
                    use_z: true,
                });
            } else {
                return Err(Error::TimeError);
            }
        }
        if let Some(sub) = claims.subject {
            if let StringOrURI::URI(sub_uri) = sub {
                if let Some(ref mut subject) = vc.credential_subject.to_single_mut() {
                    subject.id = Some(sub_uri);
                } else {
                    return Err(Error::InvalidSubject);
                }
            } else {
                return Err(Error::InvalidSubject);
            }
        }
        if let Some(id) = claims.jwt_id {
            vc.id = Some(id.try_into()?);
        }
        Ok(vc)
    }

    pub fn to_jwt_claims(&self) -> Result<JWTClaims, Error> {
        let subject_opt = self.credential_subject.to_single();

        let subject = match subject_opt {
            Some(subject) => subject
                .id
                .as_ref()
                .map(|id| StringOrURI::String(id.to_string())),
            None => None,
        };

        let vc = self.clone();

        // Copy fields from vc that are duplicated into the claims.
        let (id, issuer) = (vc.id.clone(), vc.issuer.clone());
        // Note that try_into can fail if the date_time overflows the range for NumericDate
        // for expiration_time and not_before.
        let expiration_time: Option<NumericDate> = match vc.expiration_date.as_ref() {
            Some(date) => Some(date.date_time.try_into()?),
            None => None,
        };
        let not_before: Option<NumericDate> = match vc.issuance_date.as_ref() {
            Some(date) => Some(date.date_time.try_into()?),
            None => None,
        };
        Ok(JWTClaims {
            expiration_time,
            issuer: match issuer {
                Some(Issuer::URI(uri)) => Some(StringOrURI::URI(uri)),
                Some(Issuer::Object(object_with_id)) => Some(StringOrURI::URI(object_with_id.id)),
                None => None,
            },
            not_before,
            jwt_id: id.map(|id| id.into()),
            subject,
            verifiable_credential: Some(vc),
            ..Default::default()
        })
    }

    #[deprecated(note = "Use generate_jwt")]
    pub fn encode_jwt_unsigned(&self, aud: &str) -> Result<String, Error> {
        let claims = JWTClaims {
            audience: Some(OneOrMany::One(StringOrURI::try_from(aud.to_string())?)),
            ..self.to_jwt_claims()?
        };
        Ok(ssi_jwt::encode_unsigned(&claims)?)
    }

    #[allow(deprecated)]
    #[deprecated(note = "Use generate_jwt")]
    pub fn encode_sign_jwt(&self, keys: &JWTKeys, aud: &str) -> Result<String, Error> {
        let claims = JWTClaims {
            audience: Some(OneOrMany::One(StringOrURI::try_from(aud.to_string())?)),
            ..self.to_jwt_claims()?
        };
        jwt_encode(&claims, keys)
    }

    /// Encode the Verifiable Credential as JWT. If JWK is passed, sign it, otherwise it is
    /// unsigned. Linked data proof options are translated into JWT claims if possible.
    pub async fn generate_jwt(
        &self,
        jwk: Option<&JWK>,
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
    ) -> Result<String, Error> {
        let mut options = options.clone();
        if let Some(jwk) = jwk {
            ssi_ldp::ensure_or_pick_verification_relationship(&mut options, self, jwk, resolver)
                .await?;
            // If no JWK is passed, there is no verification relationship.
        }
        let LinkedDataProofOptions {
            verification_method,
            proof_purpose,
            created,
            challenge,
            domain,
            checks,
            eip712_domain,
            type_,
            cryptosuite,
            nonce: _,
            disclosed_message_indices: _,
        } = options;
        if checks.is_some() {
            return Err(Error::UnencodableOptionClaim("checks".to_string()));
        }
        if created.is_some() {
            return Err(Error::UnencodableOptionClaim("created".to_string()));
        }
        if eip712_domain.is_some() {
            return Err(Error::UnencodableOptionClaim("eip712Domain".to_string()));
        }
        if type_.is_some() {
            return Err(Error::UnencodableOptionClaim("type".to_string()));
        }
        if cryptosuite.is_some() {
            return Err(Error::UnencodableOptionClaim("cryptosuite".to_string()));
        }
        match proof_purpose {
            None => (),
            Some(ProofPurpose::AssertionMethod) => (),
            Some(_) => return Err(Error::UnencodableOptionClaim("proofPurpose".to_string())),
        }
        let claims = JWTClaims {
            nonce: challenge,
            audience: match domain {
                Some(domain) => Some(OneOrMany::One(StringOrURI::try_from(domain)?)),
                None => None,
            },
            ..self.to_jwt_claims()?
        };
        let algorithm = if let Some(jwk) = jwk {
            jwk.get_algorithm()
                .ok_or(Error::LDP(LdpError::MissingAlgorithm))?
        } else if let Some(ref vm) = verification_method {
            resolve_key(&vm.to_string(), resolver)
                .await?
                .get_algorithm()
                .unwrap_or_default()
        } else {
            ssi_jwk::Algorithm::None
        };
        // Ensure consistency between key ID and verification method URI.
        let key_id = match (jwk.and_then(|jwk| jwk.key_id.clone()), verification_method) {
            (Some(jwk_kid), None) => Some(jwk_kid),
            (None, Some(vm_id)) => Some(vm_id.to_string()),
            (None, None) => None,
            (Some(jwk_kid), Some(vm_id)) if jwk_kid == vm_id.to_string() => Some(vm_id.to_string()),
            (Some(jwk_kid), Some(vm_id)) => {
                return Err(Error::KeyIdVMMismatch(vm_id.to_string(), jwk_kid))
            }
        };
        let header = Header {
            algorithm,
            key_id,
            ..Default::default()
        };
        let header_b64 = base64_encode_json(&header)?;
        let payload_b64 = base64_encode_json(&claims)?;
        if let Some(jwk) = jwk {
            let signing_input = header_b64 + "." + &payload_b64;
            let sig_b64 = ssi_jws::sign_bytes_b64(algorithm, signing_input.as_bytes(), jwk)?;
            let jws = signing_input + "." + &sig_b64;
            Ok(jws)
        } else {
            let jwt = header_b64 + "." + &payload_b64 + ".";
            Ok(jwt)
        }
    }

    pub async fn verify_jwt(
        jwt: &str,
        options_opt: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let (_vc, result) =
            Self::decode_verify_jwt(jwt, options_opt, resolver, context_loader).await;
        result
    }

    pub async fn decode_verify_jwt(
        jwt: &str,
        options_opt: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> (Option<Self>, VerificationResult) {
        let checks = options_opt
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        let (header_b64, payload_enc, signature_b64) = match ssi_jws::split_jws(jwt) {
            Ok(parts) => parts,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to split JWS: {err}")),
                );
            }
        };
        let ssi_jws::DecodedJWS {
            header,
            signing_input,
            payload,
            signature,
        } = match ssi_jws::decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64) {
            Ok(decoded_jws) => decoded_jws,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS: {err}")),
                );
            }
        };
        let claims: JWTClaims = match serde_json::from_slice(&payload) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS claims: {err}")),
                );
            }
        };
        let vc = match Self::from_jwt_claims(claims.clone()) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!(
                        "Unable to convert JWT claims to VC: {err}"
                    )),
                );
            }
        };
        if let Err(err) = vc.validate_unsigned() {
            return (
                None,
                VerificationResult::error(&format!("Invalid VC: {err}")),
            );
        }
        // TODO: error if any unconvertable claims
        // TODO: unify with verify function?
        let (proofs, matched_jwt) = match vc
            .filter_proofs(options_opt, Some((&header, &claims)), resolver)
            .await
        {
            Ok(matches) => matches,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to filter proofs: {err}")),
                );
            }
        };
        let verification_method = match header.key_id {
            Some(kid) => kid,
            None => {
                return (None, VerificationResult::error("JWT header missing key id"));
            }
        };
        let key = match ssi_dids::did_resolve::resolve_key(&verification_method, resolver).await {
            Ok(key) => key,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to resolve key for JWS: {err}")),
                );
            }
        };
        let mut results = VerificationResult::new();
        if matched_jwt {
            match ssi_jws::verify_bytes_warnable(header.algorithm, &signing_input, &key, &signature)
            {
                Ok(mut warnings) => {
                    results.checks.push(Check::JWS);
                    results.warnings.append(&mut warnings);
                }
                Err(err) => results
                    .errors
                    .push(format!("Unable to verify signature: {err}")),
            }
            return (Some(vc), results);
        }
        // No JWS verified: try to verify a proof.
        if proofs.is_empty() {
            return (
                None,
                VerificationResult::error("No applicable JWS or proof"),
            );
        }
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof
                .verify(&vc, resolver, context_loader, None, None)
                .await;
            results.append(&mut result);
            if results.errors.is_empty() {
                results.checks.push(Check::Proof);
                break;
            };
        }
        if checks.contains(&Check::Status) {
            results.append(&mut vc.check_status(resolver, context_loader).await);
        }
        (Some(vc), results)
    }

    pub fn validate_unsigned(&self) -> Result<(), Error> {
        if !self.type_.contains(&"VerifiableCredential".to_string()) {
            return Err(Error::MissingTypeVerifiableCredential);
        }
        if self.issuer.is_none() {
            return Err(Error::InvalidIssuer);
        }
        if self.credential_subject.is_empty() {
            // https://www.w3.org/TR/vc-data-model/#credential-subject
            // VC-Data-Model "defines a credentialSubject property for the expression of claims
            // about one or more subjects."
            // Therefore, zero credentialSubject values is considered invalid.
            return Err(Error::EmptyCredentialSubject);
        }
        for subject in &self.credential_subject {
            if subject.is_empty() {
                return Err(Error::EmptyCredentialSubject);
            }
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
            Some(proofs) => proofs.into_iter().any(|proof| proof.type_.is_zkp()),
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

    async fn filter_proofs<'a>(
        &'a self,
        options: Option<LinkedDataProofOptions>,
        jwt_params: Option<(&Header, &JWTClaims)>,
        resolver: &'a dyn DIDResolver,
    ) -> Result<(Vec<&'a Proof>, bool), String> {
        // Allow any of issuer's verification methods by default
        let mut options = options.unwrap_or_default();
        let allowed_vms = match options.verification_method.take() {
            Some(vm) => vec![vm.to_string()],
            None => {
                if let Some(ref issuer) = self.issuer {
                    let issuer_did = issuer.get_id();
                    // https://w3c.github.io/did-core/#assertion
                    // assertionMethod is the verification relationship usually used for issuing
                    // VCs.
                    let proof_purpose = options
                        .proof_purpose
                        .clone()
                        .unwrap_or(ProofPurpose::AssertionMethod);
                    get_verification_methods_for_purpose(&issuer_did, resolver, proof_purpose)
                        .await?
                } else {
                    Vec::new()
                }
            }
        };
        let matched_proofs = self
            .proof
            .iter()
            .flatten()
            .filter(|proof| proof.matches(&options, &allowed_vms))
            .collect();
        let matched_jwt = match jwt_params {
            Some((header, claims)) => jwt_matches(
                header,
                claims,
                &options,
                &Some(allowed_vms),
                &ProofPurpose::AssertionMethod,
            ),
            None => false,
        };
        Ok((matched_proofs, matched_jwt))
    }

    // TODO: factor this out of VC and VP
    pub async fn verify(
        &self,
        options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let nonce = match options.as_ref() {
            Some(ldp_options) => ldp_options.nonce.clone(),
            None => None,
        };
        let disclosed_message_indices = match options.as_ref() {
            Some(ldp_options) => ldp_options.disclosed_message_indices.clone(),
            None => None,
        };
        let checks = options
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        let (proofs, _) = match self.filter_proofs(options, None, resolver).await {
            Ok(proofs) => proofs,
            Err(err) => {
                return VerificationResult::error(&format!("Unable to filter proofs: {err}"));
            }
        };
        if proofs.is_empty() {
            return VerificationResult::error("No applicable proof");
            // TODO: say why, e.g. expired
        }

        let mut results = VerificationResult::new();
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof
                .verify(
                    self,
                    resolver,
                    context_loader,
                    nonce.as_ref(),
                    disclosed_message_indices.as_ref(),
                )
                .await;
            results.append(&mut result);
            if result.errors.is_empty() {
                results.checks.push(Check::Proof);
                break;
            };
        }
        if checks.contains(&Check::Status) {
            results.append(&mut self.check_status(resolver, context_loader).await);
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
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<Proof, LdpError> {
        LinkedDataProofs::sign(self, options, resolver, context_loader, jwk, None).await
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<ProofPreparation, LdpError> {
        LinkedDataProofs::prepare(self, options, resolver, context_loader, public_key, None).await
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

    /// Check the credentials [status](https://www.w3.org/TR/vc-data-model/#status)
    pub async fn check_status(
        &self,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let status = match self.credential_status {
            Some(ref status) => status,
            None => return VerificationResult::error("Missing credentialStatus"),
        };
        let status_value = match serde_json::to_value(status.clone()) {
            Ok(status) => status,
            Err(e) => {
                return VerificationResult::error(&format!(
                    "Unable to convert credentialStatus: {e}"
                ))
            }
        };
        let checkable_status: CheckableStatus = match serde_json::from_value(status_value) {
            Ok(checkable_status) => checkable_status,
            Err(e) => {
                return VerificationResult::error(&format!("Unable to parse credentialStatus: {e}"))
            }
        };
        let mut result = checkable_status.check(self, resolver, context_loader).await;
        if !result.errors.is_empty() {
            return result;
        }
        result.checks.push(Check::Status);
        result
    }

    pub async fn get_nquad_positions(
        &self,
        selectors: &[String],
        context_loader: &mut ContextLoader,
    ) -> Result<Vec<u32>, Error> {
        let nquads = ssi_ldp::to_nquads(self, context_loader).await?;
        let mut positions = Vec::new();
        let mut index: u32 = 2;
        for nq in nquads.iter() {
            let split: Vec<&str> = nq.split(' ').collect();
            let middle = split[1];

            for s in selectors.iter() {
                let suffix = "/".to_owned() + s + ">";
                if middle.ends_with(suffix.as_str()) {
                    positions.push(index);
                    break;
                }
            }

            index += 1;
        }
        Ok(positions)
    }
}

impl CheckableStatus {
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        match self {
            Self::RevocationList2020Status(status) => {
                status.check(credential, resolver, context_loader).await
            }
            Self::StatusList2021Entry(status) => {
                status.check(credential, resolver, context_loader).await
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl LinkedDataDocument for Credential {
    fn get_contexts(&self) -> Result<Option<String>, LdpError> {
        Ok(Some(serde_json::to_string(&self.context)?))
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
        context_loader: &mut ContextLoader,
    ) -> Result<DataSet, LdpError> {
        let mut copy = self.clone();
        copy.proof = None;
        let json = ssi_json_ld::syntax::to_value_with(copy, Default::default).unwrap();
        Ok(json_to_dataset(
            json,
            context_loader,
            parent
                .map(LinkedDataDocument::get_contexts)
                .transpose()?
                .flatten()
                .as_deref()
                .map(parse_ld_context)
                .transpose()?,
        )
        .await?)
    }

    fn to_value(&self) -> Result<Value, LdpError> {
        Ok(serde_json::to_value(self)?)
    }

    fn get_issuer(&self) -> Option<&str> {
        match self.issuer {
            Some(ref issuer) => Some(issuer.get_id_ref()),
            None => None,
        }
    }

    fn get_default_proof_purpose(&self) -> Option<ProofPurpose> {
        Some(ProofPurpose::AssertionMethod)
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

    pub fn from_jwt_claims(claims: JWTClaims) -> Result<Self, Error> {
        let mut vp = match claims.verifiable_presentation {
            Some(vp) => vp,
            None => return Err(Error::MissingPresentation),
        };
        if let Some(StringOrURI::URI(issuer_uri)) = claims.issuer {
            vp.holder = Some(issuer_uri);
        }
        if let Some(id) = claims.jwt_id {
            vp.id = Some(id.try_into()?);
        }
        Ok(vp)
    }

    pub fn to_jwt_claims(&self) -> Result<JWTClaims, Error> {
        let vp = self.clone();
        let (id, holder) = (vp.id.clone(), vp.holder.clone());
        Ok(JWTClaims {
            issuer: holder.map(|id| id.into()),
            jwt_id: id.map(|id| id.into()),
            verifiable_presentation: Some(vp),
            ..Default::default()
        })
    }

    #[allow(deprecated)]
    #[deprecated(note = "Use generate_jwt")]
    pub fn encode_sign_jwt(&self, keys: &JWTKeys, aud: &str) -> Result<String, Error> {
        let claims = JWTClaims {
            audience: Some(OneOrMany::One(StringOrURI::try_from(aud.to_string())?)),
            ..self.to_jwt_claims()?
        };
        jwt_encode(&claims, keys)
    }

    /// Encode the Verifiable Presentation as JWT. If JWK is passed, sign it, otherwise it is
    /// unsigned. Linked data proof options are translated into JWT claims if possible.
    pub async fn generate_jwt(
        &self,
        jwk: Option<&JWK>,
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
    ) -> Result<String, Error> {
        let mut options = options.clone();
        if let Some(jwk) = jwk {
            ssi_ldp::ensure_or_pick_verification_relationship(&mut options, self, jwk, resolver)
                .await?;
            // If no JWK is passed, there is no verification relationship.
        }
        let LinkedDataProofOptions {
            verification_method,
            proof_purpose,
            created,
            challenge,
            domain,
            checks,
            eip712_domain,
            type_,
            cryptosuite,
            nonce: _,
            disclosed_message_indices: _,
        } = options;
        if checks.is_some() {
            return Err(Error::UnencodableOptionClaim("checks".to_string()));
        }
        if created.is_some() {
            return Err(Error::UnencodableOptionClaim("created".to_string()));
        }
        if eip712_domain.is_some() {
            return Err(Error::UnencodableOptionClaim("eip712Domain".to_string()));
        }
        if type_.is_some() {
            return Err(Error::UnencodableOptionClaim("type".to_string()));
        }
        if cryptosuite.is_some() {
            return Err(Error::UnencodableOptionClaim("cryptosuite".to_string()));
        }
        match proof_purpose {
            None => (),
            Some(ProofPurpose::Authentication) => (),
            Some(_) => return Err(Error::UnencodableOptionClaim("proofPurpose".to_string())),
        }
        let claims = JWTClaims {
            nonce: challenge,
            audience: match domain {
                Some(domain) => Some(OneOrMany::One(StringOrURI::try_from(domain)?)),
                None => None,
            },
            ..self.to_jwt_claims()?
        };
        let algorithm = if let Some(jwk) = jwk {
            jwk.get_algorithm()
                .ok_or(Error::LDP(LdpError::MissingAlgorithm))?
        } else if let Some(ref vm) = verification_method {
            resolve_key(&vm.to_string(), resolver)
                .await?
                .get_algorithm()
                .unwrap_or_default()
        } else {
            ssi_jwk::Algorithm::None
        };
        let key_id = match (jwk.and_then(|jwk| jwk.key_id.clone()), verification_method) {
            (Some(jwk_kid), None) => Some(jwk_kid),
            (None, Some(vm_id)) => Some(vm_id.to_string()),
            (None, None) => None,
            (Some(jwk_kid), Some(vm_id)) if jwk_kid == vm_id.to_string() => Some(vm_id.to_string()),
            (Some(jwk_kid), Some(vm_id)) => {
                return Err(Error::KeyIdVMMismatch(vm_id.to_string(), jwk_kid))
            }
        };
        let header = Header {
            algorithm,
            key_id,
            ..Default::default()
        };
        let header_b64 = base64_encode_json(&header)?;
        let payload_b64 = base64_encode_json(&claims)?;
        if let Some(jwk) = jwk {
            let signing_input = header_b64 + "." + &payload_b64;
            let sig_b64 = ssi_jws::sign_bytes_b64(algorithm, signing_input.as_bytes(), jwk)?;
            let jws = signing_input + "." + &sig_b64;
            Ok(jws)
        } else {
            let jwt = header_b64 + "." + &payload_b64 + ".";
            Ok(jwt)
        }
    }

    // Decode and verify a JWT-encoded Verifiable Presentation. On success, returns the Verifiable
    // Presentation and verification result.
    pub async fn decode_verify_jwt(
        jwt: &str,
        options_opt: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> (Option<Self>, VerificationResult) {
        let checks = options_opt
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        if checks.contains(&Check::Status) {
            // TODO: apply check to embedded VCs
            return (
                None,
                VerificationResult::error(
                    "credentialStatus check not valid for VerifiablePresentation",
                ),
            );
        }
        // let mut options = options_opt.unwrap_or_default();
        let (header_b64, payload_enc, signature_b64) = match ssi_jws::split_jws(jwt) {
            Ok(parts) => parts,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to split JWS: {err}")),
                );
            }
        };
        let ssi_jws::DecodedJWS {
            header,
            signing_input,
            payload,
            signature,
        } = match ssi_jws::decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64) {
            Ok(decoded_jws) => decoded_jws,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS: {err}")),
                );
            }
        };
        let claims: JWTClaims = match serde_json::from_slice(&payload) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS claims: {err}")),
                );
            }
        };
        let vp = match Self::from_jwt_claims(claims.clone()) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!(
                        "Unable to convert JWT claims to VP: {err}"
                    )),
                );
            }
        };
        if let Err(err) = vp.validate_unsigned() {
            return (
                None,
                VerificationResult::error(&format!("Invalid VP: {err}")),
            );
        }
        let mut results = VerificationResult::new();
        // TODO: error if any unconvertable claims
        // TODO: unify with verify function?
        let (proofs, matched_jwt) = match vp
            .filter_proofs(options_opt, Some((&header, &claims)), resolver)
            .await
        {
            Ok(matches) => matches,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to filter proofs: {err}")),
                );
            }
        };
        let verification_method = match header.key_id {
            Some(kid) => kid,
            None => {
                return (None, VerificationResult::error("JWT header missing key id"));
            }
        };
        let key = match ssi_dids::did_resolve::resolve_key(&verification_method, resolver).await {
            Ok(key) => key,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to resolve key for JWS: {err}")),
                );
            }
        };
        if matched_jwt {
            match ssi_jws::verify_bytes_warnable(header.algorithm, &signing_input, &key, &signature)
            {
                Ok(mut warnings) => {
                    results.checks.push(Check::JWS);
                    results.warnings.append(&mut warnings);
                }
                Err(err) => results
                    .errors
                    .push(format!("Unable to filter proofs: {err}")),
            }
            return (Some(vp), results);
        }
        // No JWS verified: try to verify a proof.
        if proofs.is_empty() {
            return (
                None,
                VerificationResult::error("No applicable JWS or proof"),
            );
        }
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof
                .verify(&vp, resolver, context_loader, None, None)
                .await;
            if result.errors.is_empty() {
                result.checks.push(Check::Proof);
                return (Some(vp), result);
            };
            results.append(&mut result);
        }
        (Some(vp), results)
    }

    pub async fn verify_jwt(
        jwt: &str,
        options_opt: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let (_vp, result) =
            Self::decode_verify_jwt(jwt, options_opt, resolver, context_loader).await;
        result
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
                    Credential::from_jwt_unsigned_embedded(jwt)?;
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
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<Proof, Error> {
        Ok(LinkedDataProofs::sign(self, options, resolver, context_loader, jwk, None).await?)
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<ProofPreparation, Error> {
        Ok(
            LinkedDataProofs::prepare(self, options, resolver, context_loader, public_key, None)
                .await?,
        )
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

    async fn filter_proofs<'a>(
        &'a self,
        options: Option<LinkedDataProofOptions>,
        jwt_params: Option<(&Header, &JWTClaims)>,
        resolver: &dyn DIDResolver,
    ) -> Result<(Vec<&Proof>, bool), Error> {
        // Allow any of holder's verification methods matching proof purpose by default
        let mut options = options.unwrap_or_else(|| LinkedDataProofOptions {
            proof_purpose: Some(ProofPurpose::Authentication),
            ..Default::default()
        });
        let restrict_allowed_vms = match options.verification_method.take() {
            Some(vm) => Some(vec![vm.to_string()]),
            None => {
                if let Some(URI::String(ref _holder)) = self.holder {
                    let proof_purpose = options
                        .proof_purpose
                        .clone()
                        .unwrap_or(ProofPurpose::Authentication);
                    Some(
                        self.get_verification_methods_for_purpose_bindable(resolver, proof_purpose)
                            .await?,
                    )
                } else {
                    None
                }
            }
        };
        let matched_proofs = self
            .proof
            .iter()
            .flatten()
            .filter(|proof| {
                proof.matches_options(&options)
                    && if let Some(ref allowed_vms) = restrict_allowed_vms {
                        proof.matches_vms(allowed_vms)
                    } else {
                        // No verificationMethod verify option or holder property: allow any VM.
                        true
                    }
            })
            .collect();
        let matched_jwt = match jwt_params {
            Some((header, claims)) => jwt_matches(
                header,
                claims,
                &options,
                &restrict_allowed_vms,
                &ProofPurpose::Authentication,
            ),
            None => false,
        };
        Ok((matched_proofs, matched_jwt))
    }

    // TODO: factor this out of VC and VP
    pub async fn verify(
        &self,
        options: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let checks = options
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        if checks.contains(&Check::Status) {
            // TODO: apply check to embedded VCs
            return VerificationResult::error(
                "credentialStatus check not valid for VerifiablePresentation",
            );
        }
        let mut results = VerificationResult::new();
        let (proofs, _) = match self.filter_proofs(options, None, resolver).await {
            Ok(proofs) => proofs,
            Err(err) => {
                return VerificationResult::error(&format!("Unable to filter proofs: {err}"));
            }
        };
        if proofs.is_empty() {
            return VerificationResult::error("No applicable proof");
            // TODO: say why, e.g. expired
        }
        // Try verifying each proof until one succeeds
        for proof in proofs {
            let mut result = proof
                .verify(self, resolver, context_loader, None, None)
                .await;
            if result.errors.is_empty() {
                result.checks.push(Check::Proof);
                return result;
            };
            results.append(&mut result);
        }
        results
    }

    /// Like [get_verification_methods_for_purpose] but including VMs of DIDs authorized to
    /// act as holder via [Presentation::holder_binding].
    async fn get_verification_methods_for_purpose_bindable(
        &self,
        resolver: &dyn DIDResolver,
        proof_purpose: ProofPurpose,
    ) -> Result<Vec<String>, Error> {
        let authorized_holders = self.get_authorized_holders().await?;
        let vmms = ssi_dids::did_resolve::get_verification_methods_for_all(
            authorized_holders
                .iter()
                .map(|x| x.as_str())
                .collect::<Vec<&str>>()
                .as_ref(),
            proof_purpose.clone(),
            resolver,
        )
        .await?;
        Ok(vmms.into_keys().collect())
    }

    pub(crate) async fn get_authorized_holders(&self) -> Result<Vec<String>, Error> {
        let mut holders = match (self.holder.as_ref(), self.holder_binding.as_ref()) {
            (Some(_), Some(_)) | (None, None) => vec![],
            (Some(h), None) => vec![h.to_string()],
            (None, Some(_)) => return Err(Error::MissingHolder),
        };
        for holder_binding in self.holder_binding.iter().flatten() {
            match &holder_binding {
                #[cfg(test)]
                HolderBinding::ExampleHolderBinding2022 { to, from: _ } => {
                    // TODO: error if term does not expand to expected IRI
                    // TODO: check proof signed by binding.from
                    if self.holder.is_none() || Some(to) != self.holder.as_ref() {
                        continue;
                    }
                    // let signature = base64::decode_config(proof, base64::URL_SAFE_NO_PAD)?;
                    holders.push(to.to_string());
                }
                HolderBinding::CacaoDelegationHolderBinding2022 { cacao_delegation } => {
                    match cacao_delegation
                        .validate_presentation(
                            self.verifiable_credential.as_ref(),
                            self.holder.as_ref(),
                        )
                        .await
                    {
                        Ok(Some(h)) => holders.push(h),
                        Ok(None) => continue,
                        Err(e) => Err(e)?,
                    }
                }
                HolderBinding::Unknown => {
                    // TODO: return warning or error for unknown holder binding?
                    return Err(Error::UnsupportedHolderBinding);
                }
            }
        }
        Ok(holders)
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
            holder_binding: None,
            property_set: None,
        }
    }
}

/// Get a DID's first verification method
pub async fn get_verification_method(did: &str, resolver: &dyn DIDResolver) -> Option<String> {
    let doc = match ssi_dids::did_resolve::easy_resolve(did, resolver).await {
        Ok(doc) => doc,
        Err(_) => return None,
    };
    let vms_auth = doc
        .get_verification_method_ids(ProofPurpose::Authentication)
        .ok();
    if let Some(id) = vms_auth.iter().flatten().next() {
        return Some(id.to_owned());
    }
    let vms_assert = doc
        .get_verification_method_ids(ProofPurpose::AssertionMethod)
        .ok();
    vms_assert.iter().flatten().next().cloned()
}

/// Resolve a DID and get its the verification methods from its DID document.
#[deprecated(note = "Use get_verification_methods_for_purpose")]
pub async fn get_verification_methods(
    did: &str,
    resolver: &dyn DIDResolver,
) -> Result<Vec<String>, String> {
    let doc = ssi_dids::did_resolve::easy_resolve(did, resolver)
        .await
        .map_err(String::from)?;
    let vms = doc
        .verification_method
        .iter()
        .flatten()
        .map(|vm| vm.get_id(did))
        .collect();
    Ok(vms)
}

pub async fn get_verification_methods_for_purpose(
    did: &str,
    resolver: &dyn DIDResolver,
    proof_purpose: ProofPurpose,
) -> Result<Vec<String>, String> {
    let vmms =
        ssi_dids::did_resolve::get_verification_methods(did, proof_purpose.clone(), resolver)
            .await
            .map_err(String::from)?;
    Ok(vmms.into_keys().collect())
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl LinkedDataDocument for Presentation {
    fn get_contexts(&self) -> Result<Option<String>, LdpError> {
        Ok(Some(serde_json::to_string(&self.context)?))
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
        context_loader: &mut ContextLoader,
    ) -> Result<DataSet, LdpError> {
        let mut copy = self.clone();
        copy.proof = None;
        let json = ssi_json_ld::syntax::to_value_with(copy, Default::default).unwrap();
        Ok(json_to_dataset(
            json,
            context_loader,
            parent
                .map(LinkedDataDocument::get_contexts)
                .transpose()?
                .flatten()
                .as_deref()
                .map(parse_ld_context)
                .transpose()?,
        )
        .await?)
    }

    fn to_value(&self) -> Result<Value, LdpError> {
        Ok(serde_json::to_value(self)?)
    }

    fn get_issuer(&self) -> Option<&str> {
        match self.holder {
            Some(ref holder) => Some(holder.as_str()),
            None => None,
        }
    }

    fn get_default_proof_purpose(&self) -> Option<ProofPurpose> {
        Some(ProofPurpose::Authentication)
    }
}

/// Evaluate if a JWT (header and claims) matches some linked data proof options.
fn jwt_matches(
    header: &Header,
    claims: &JWTClaims,
    options: &LinkedDataProofOptions,
    restrict_allowed_vms: &Option<Vec<String>>,
    expected_proof_purpose: &ProofPurpose,
) -> bool {
    let LinkedDataProofOptions {
        verification_method,
        proof_purpose,
        created,
        challenge,
        domain,
        ..
    } = options;
    if let Some(ref vm) = verification_method {
        assert_local!(header.key_id.as_ref() == Some(&vm.to_string()));
    }
    if let Some(kid) = header.key_id.as_ref() {
        if let Some(allowed_vms) = restrict_allowed_vms {
            assert_local!(allowed_vms.contains(kid));
        }
    }
    if let Some(nbf) = claims.not_before {
        let nbf_date_time: LocalResult<DateTime<Utc>> = nbf.into();
        if let Some(time) = nbf_date_time.latest() {
            assert_local!(created.unwrap_or_else(Utc::now) >= time);
        } else {
            return false;
        }
    }
    if let Some(exp) = claims.expiration_time {
        let exp_date_time: LocalResult<DateTime<Utc>> = exp.into();
        if let Some(time) = exp_date_time.earliest() {
            assert_local!(Utc::now() < time);
        } else {
            return false;
        }
    }
    if let Some(ref challenge) = challenge {
        assert_local!(claims.nonce.as_ref() == Some(challenge));
    }
    if let Some(ref aud) = claims.audience {
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        //   Each principal intended to process the JWT MUST
        //   identify itself with a value in the audience claim.
        // https://www.w3.org/TR/vc-data-model/#jwt-encoding
        //   aud MUST represent (i.e., identify) the intended audience of the verifiable
        //   presentation (i.e., the verifier intended by the presenting holder to receive and
        //   verify the verifiable presentation).
        if let Some(domain) = domain {
            // Use domain for audience, and require a match.
            if !aud.into_iter().any(|aud| aud.as_str() == domain) {
                return false;
            }
        } else {
            // TODO: allow using verifier DID for audience?
            return false;
        }
    }
    if let Some(ref proof_purpose) = proof_purpose {
        if proof_purpose != expected_proof_purpose {
            return false;
        }
    }
    // TODO: support more claim checking via additional LDP options
    true
}

fn select_fields(subject: &CredentialSubject, selectors: &[String]) -> Map<String, Value> {
    let mut selected = Map::new();

    match &subject.property_set {
        Some(properties) => {
            'outer: for (k, v) in properties {
                for s in selectors {
                    if k.as_str() == s {
                        selected.insert(k.clone(), v.clone());
                        continue 'outer;
                    }
                }
            }
        }
        None => (),
    }

    //eprintln!("Selected properties: {:?}", &selected);
    selected
}

pub async fn derive_credential(
    document: &Credential,
    proof_nonce: &str,
    selectors: &[String],
    did_resolver: &dyn DIDResolver,
) -> Result<Credential, Error> {
    let mut derived_credential = document.clone();

    let proofs = derived_credential.proof.unwrap();

    let proof = match proofs {
        OneOrMany::One(proof) => proof,
        OneOrMany::Many(_) => unimplemented!(), // todo: handle multiple proof case
    };

    // before zeroing this out, this is needed to generate the proof
    derived_credential.proof = None;

    match &derived_credential.credential_subject {
        OneOrMany::One(subject) => {
            let selected_fields = select_fields(subject, selectors);

            let mut new_subject = subject.clone();
            new_subject.property_set = Some(selected_fields);
            derived_credential.credential_subject = OneOrMany::One(new_subject);
        }
        OneOrMany::Many(subjects) => {
            let mut new_subjects: Vec<CredentialSubject> = Vec::new();

            for s in subjects {
                let selected_fields = select_fields(s, selectors);

                let mut new_subject = s.clone();
                new_subject.property_set = Some(selected_fields);
                new_subjects.push(new_subject);
            }

            derived_credential.credential_subject = OneOrMany::Many(new_subjects);
        }
    }

    let proof =
        ssi_ldp::generate_bbs_signature_pok(document, proof_nonce, &proof, did_resolver, selectors)
            .await?;
    derived_credential.add_proof(proof);

    Ok(derived_credential)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;
    use ssi_dids::{
        did_resolve::DereferencingInputMetadata, example::DIDExample, VerificationMethodMap,
    };
    use ssi_json_ld::urdna2015;
    use ssi_jws::sign_bytes_b64;
    use ssi_ldp::{ProofSuite, ProofSuiteType};

    #[test]
    fn numeric_date() {
        assert_eq!(
            NumericDate::try_from_seconds(NumericDate::MIN.as_seconds()).unwrap(),
            NumericDate::MIN,
            "NumericDate::MIN value did not survive round trip"
        );
        assert_eq!(
            NumericDate::try_from_seconds(NumericDate::MAX.as_seconds()).unwrap(),
            NumericDate::MAX,
            "NumericDate::MAX value did not survive round trip"
        );

        assert!(
            NumericDate::try_from_seconds(NumericDate::MIN.as_seconds() - 1.0e-6).is_err(),
            "NumericDate::MIN-1.0e-6 value did not hit out-of-range error"
        );
        assert!(
            NumericDate::try_from_seconds(NumericDate::MAX.as_seconds() + 1.0e-6).is_err(),
            "NumericDate::MAX+1.0e-6 value did not hit out-of-range error"
        );

        assert!(
            NumericDate::try_from_seconds(NumericDate::MIN.as_seconds() + 1.0e-6).is_ok(),
            "NumericDate::MIN-1.0e-6 value did not hit out-of-range error"
        );
        assert!(
            NumericDate::try_from_seconds(NumericDate::MAX.as_seconds() - 1.0e-6).is_ok(),
            "NumericDate::MAX+1.0e-6 value did not hit out-of-range error"
        );

        let one_microsecond = Duration::microseconds(1);
        assert_eq!(
            (NumericDate::MIN + one_microsecond) - one_microsecond,
            NumericDate::MIN,
            "NumericDate::MIN+1.0e-6 wasn't correctly represented"
        );
        assert_eq!(
            (NumericDate::MAX - one_microsecond) + one_microsecond,
            NumericDate::MAX,
            "NumericDate::MAX-1.0e-6 wasn't correctly represented"
        );

        // At the MIN and MAX, increasing by half a microsecond shouldn't alter MIN or MAX.
        assert_eq!(
            NumericDate::MIN - Duration::nanoseconds(500),
            NumericDate::MIN,
            "NumericDate::MIN isn't the true min"
        );
        assert_eq!(
            NumericDate::MAX + Duration::nanoseconds(500),
            NumericDate::MAX,
            "NumericDate::MAX isn't the true max"
        );
    }

    #[test]
    #[should_panic]
    fn numeric_date_out_of_range_panic_0() {
        // At the MIN, subtracting a microsecond should put it just out of range.
        let _ = NumericDate::MIN - Duration::microseconds(1);
    }

    #[test]
    #[should_panic]
    fn numeric_date_out_of_range_panic_1() {
        // At the MAX, adding a microsecond should put it just out of range.
        let _ = NumericDate::MAX + Duration::microseconds(1);
    }

    pub const EXAMPLE_REVOCATION_2020_LIST_URL: &str = "https://example.test/revocationList.json";
    pub const EXAMPLE_REVOCATION_2020_LIST: &[u8] =
        include_bytes!("../../tests/revocationList.json");

    pub const EXAMPLE_STATUS_LIST_2021_URL: &str = "https://example.com/credentials/status/3";
    pub const EXAMPLE_STATUS_LIST_2021: &[u8] = include_bytes!("../../tests/statusList.json");

    const JWK_JSON: &str = include_str!("../../tests/rsa2048-2020-08-25.json");
    const JWK_JSON_BAR: &str = include_str!("../../tests/ed25519-2021-06-16.json");

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
            panic!();
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
    fn test_vc_date_time_roundtrip() {
        let expected_utc_now = chrono::Utc::now();
        let vc_date_time_now = VCDateTime::from(expected_utc_now);
        let roundtripped_utc_now = chrono::DateTime::<chrono::Utc>::from(vc_date_time_now);
        assert_eq!(roundtripped_utc_now, expected_utc_now);
    }

    #[async_std::test]
    async fn generate_jwt() {
        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/192783",
            "type": "VerifiableCredential",
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-25T11:26:53Z",
            "credentialSubject": {
                "id": "did:example:a6c78986cc36418b95a22d7f736",
                "spouse": "Example Person"
            }
        }"###;

        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
        let vc: Credential = serde_json::from_str(vc_str).unwrap();
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let options = LinkedDataProofOptions {
            domain: Some(aud),
            checks: None,
            created: None,
            ..Default::default()
        };
        let resolver = &DIDExample;
        let signed_jwt = vc
            .generate_jwt(Some(&key), &options, resolver)
            .await
            .unwrap();
        println!("{:?}", signed_jwt);

        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let (vc_opt, verification_result) = Credential::decode_verify_jwt(
            &signed_jwt,
            Some(options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", verification_result);
        let _vc = vc_opt.unwrap();
        assert_eq!(verification_result.errors.len(), 0);
    }

    #[async_std::test]
    async fn decode_verify_jwt() {
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/192783",
            "type": "VerifiableCredential",
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-25T11:26:53Z",
            "credentialSubject": {
                "id": "did:example:a6c78986cc36418b95a22d7f736",
                "spouse": "Example Person"
            }
        }"###;

        let vc = Credential {
            expiration_date: Some(VCDateTime::from(Utc::now() + chrono::Duration::weeks(1))),
            ..serde_json::from_str(vc_str).unwrap()
        };
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let options = LinkedDataProofOptions {
            domain: Some(aud),
            checks: None,
            created: None,
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let signed_jwt = vc
            .generate_jwt(Some(&key), &options, &DIDExample)
            .await
            .unwrap();
        println!("{:?}", signed_jwt);

        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let (vc1_opt, verification_result) = Credential::decode_verify_jwt(
            &signed_jwt,
            Some(options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
        let vc1 = vc1_opt.unwrap();
        assert_eq!(vc.id, vc1.id);

        // Test expiration date
        let vc = Credential {
            expiration_date: Some(VCDateTime::from(Utc::now() - chrono::Duration::weeks(1))),
            ..vc
        };
        let signed_jwt = vc
            .generate_jwt(Some(&key), &options, &DIDExample)
            .await
            .unwrap();
        let (_vc_opt, verification_result) = Credential::decode_verify_jwt(
            &signed_jwt,
            Some(options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", verification_result);
        assert!(!verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn decode_verify_jwt_single_array_subject() {
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": "VerifiableCredential",
            "issuer": "did:example:foo",
            "issuanceDate": "2021-09-28T19:58:30Z",
            "credentialSubject": [{
                "id": "did:example:a6c78986cc36418b95a22d7f736",
                "spouse": "Example Person"
            }]
        }"###;

        let vc = Credential {
            expiration_date: Some(VCDateTime::from(Utc::now() + chrono::Duration::weeks(1))),
            ..serde_json::from_str(vc_str).unwrap()
        };
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let options = LinkedDataProofOptions {
            domain: Some(aud),
            checks: None,
            created: None,
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let signed_jwt = vc
            .generate_jwt(Some(&key), &options, &DIDExample)
            .await
            .unwrap();
        println!("{:?}", signed_jwt);

        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let (_vc1_opt, verification_result) = Credential::decode_verify_jwt(
            &signed_jwt,
            Some(options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn generate_unsigned_jwt() {
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/192783",
            "type": "VerifiableCredential",
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-25T11:26:53Z",
            "credentialSubject": {
                "id": "did:example:a6c78986cc36418b95a22d7f736",
                "spouse": "Example Person"
            }
        }"###;
        let vc = Credential {
            expiration_date: Some(VCDateTime::from(Utc::now() + chrono::Duration::weeks(1))),
            ..serde_json::from_str(vc_str).unwrap()
        };
        let aud = "did:example:90336644520443d28ba78beb949".to_string();
        let options = LinkedDataProofOptions {
            domain: Some(aud),
            checks: None,
            created: None,
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let unsigned_jwt_vc = vc.generate_jwt(None, &options, &DIDExample).await.unwrap();
        let signature = sign_bytes_b64(
            key.get_algorithm().unwrap(),
            unsigned_jwt_vc.trim_end_matches('.').as_bytes(),
            &key,
        )
        .unwrap();
        let signed_jwt = [unsigned_jwt_vc, signature].join("");

        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let (vc1_opt, verification_result) = Credential::decode_verify_jwt(
            &signed_jwt,
            Some(options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        assert_eq!(vec![String::new(); 0], verification_result.errors);
        let vc1 = vc1_opt.unwrap();
        assert_eq!(vc.id, vc1.id);
    }

    #[async_std::test]
    async fn credential_issue_verify() {
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

        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
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
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(!verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn credential_issue_verify_bbs() {
        let cred_str = include_str!("../../tests/bbsplus-jane-doe-unsigned-vc.json");
        let mut vc = Credential::from_json_unsigned(cred_str).unwrap();
        let key_str = include_str!("../../tests/bbsplus-issuer-key.jwk");
        let key: JWK = serde_json::from_str(key_str).unwrap();

        let vm_str = include_str!("../../tests/bbsplus-verification-method.txt").trim();
        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(vm_str.to_owned())),
            ..Default::default()
        };

        let mut context_loader = ssi_json_ld::ContextLoader::default();

        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();

        eprintln!("{}", serde_json::to_string_pretty(&proof).unwrap());

        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        eprintln!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        let proof_nonce = "V3dG/xYTV7drtMkfXy5Dfj5iFj+CguQTFzVdYCYMMGE=";
        let selectors = vec![String::from("familyName"), String::from("givenName")];
        let positions = vc
            .get_nquad_positions(selectors.as_slice(), &mut context_loader)
            .await
            .unwrap();
        let mut derived_vc = derive_credential(&vc, proof_nonce, selectors.as_slice(), &DIDExample)
            .await
            .unwrap();

        let verify_options = LinkedDataProofOptions {
            nonce: Some(String::from(proof_nonce)),
            disclosed_message_indices: Some(positions.into_iter().map(|x| x as usize).collect()),
            ..Default::default()
        };
        let dc_verification_result = derived_vc
            .verify(
                Some(verify_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        eprintln!(
            "Derived credential verification result: {:?}",
            &dc_verification_result
        );
        assert!(dc_verification_result.errors.is_empty());

        // Replace the signature with another valid signature and ensure it fails.
        match vc.proof {
            None => unreachable!(),
            Some(OneOrMany::Many(_)) => unreachable!(),
            Some(OneOrMany::One(ref mut proof)) => {
                proof.jws = Some(String::from("eyJhbGciOiJCTFMxMjM4MUcyIiwiY3JpdCI6WyJiNjQiXSwiYjY0IjpmYWxzZX0..hgCsbX-km2b77sR7GQHcDsGHzgo004nOFmCjvH6ofL99YJVHsy3MXjiyC-i6MMVcFMVeCUP8kWMij9CMUUywr9f5ePQzc0rFRrAKqQg4nZpYMCz4qKa5vGceQo7cge_jvx7ewU0Sojf4nSJxPA41_Q"));
            }
        }
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        assert!(!verification_result.errors.is_empty());

        match derived_vc.proof {
            None => unreachable!(),
            Some(OneOrMany::Many(_)) => unreachable!(),
            Some(OneOrMany::One(ref mut proof)) => {
                proof.jws = Some(String::from("eyJhbGciOiJCTFMxMjM4MUcyIiwiY3JpdCI6WyJiNjQiXSwiYjY0IjpmYWxzZX0..AAAN3JXyeXht4pWhu54Rb0hBk5-aa8p72LyBZpXlQihUZ_txlLDjkp8EgOYKmTvGGrNgpLlhRc7nkZoM-oOwGj63XtUGJiFGwaDZA4iXkDVPo-9xmf_d6VZDisOSm2Pc0q0oYI2s2XV0q5_BGT4CdDRewRDQbn386nTRp272v4Amq_AiK05z6coKdnHMJPEpbdEH0QAAAHSrLnR6TAaoxfxHdBKVXL2q8N_51DTPtqiiKrD5kQrD_NAoZQ_D6DU8arwWayQeXcIAAAACJAWfAvZKJTehmKvc_FlWOMMxSRf2pDm-46oOb3ApyQktT1yIewg_MrheqHINcFxLtEtfVhqq9gaZ4jG4k4ixX6CZ32l7fT-71jl5Frxcomw0Xd9CfsxwpSQmqZQr_In5wiRp2qrik9AUaaaWklISBAAAAGVgRdKo-BXXEkrOBvTTTTIZNwz16NzxrJk7sXBNm3upFgGQir1huK-rU2tw7ilL6lkEH8BF-dh1U5KtRCjY-JMMIyIyyXfF_nBtdXx3e8ElTKm7pBxGJuvArnyebUzEVDwlkCl0HIzucHwDGDowTKx4NBA5d2yI_RpGXFItcOK-C0d5R7GRfm-UcVJq25LO096TjJ-giq3LRweuUUmfNaBDWJA7_pTHKU4EPq283J3KCCIe2zKeah0Nwctd1snGCZFk2uFWlzEf0O0mM8QNH_zlzRx_Ho25mmsmglkFIH1ZBW-mc1HA683hV0ftIovUJ_D-2Lwo8FZ0D2RqYshMcqI3FMX3YzppwXdoYpu8D2d6U1eFT4UnGxqnNvuscNLjbLlH32epfSWWF782pTxmO6KLwkLF1Ol6ME1NYWsdk4UCIRQDclH_bVkNuHI5qaIIIMsBM1wvEhd08-IEuot3XC3LXvcS2bUiNYQgQ8rlUmScpLUsyHjzYPTxMNQguIg6qe9W5maqF6EtnnfZ1_v8ku_fMhk9t2S1WZXvhESrRdp0Z2_q1ny9yea-frZPYjVDnsOyeNQrM3O5aguAFXniF71jC664-b8nolrI3seqWpLsIVmIN-eDeC-QmOTIgDk78x1Lr4btQRwck0OAK3nRlHOP26uHsDMaMQDuescledFPihiUQIenPQXuQuP9I1nLLZyW2zuAzTbnHRjBLcoWV2gKHk-Y70P9mulZl4x5Bm5U1QXoLsZyJmWEmp4y8sReCzAw2uHFtJrdj_AsLG-xGlkt7Ec4BqolZIHAr9gIZv7a0Un6DDxw6rbTjsXgFoQKKhJ13Fi1z2wRlsErCdSImeuPBy-6Txg0aENELdvBh6nRgaBpW8_movD62c8JBueIxvgUiRUmc-yenITYMIo2hDyYsif_zgH6V1QXlVrMPFMEv0_H6TXE1qgDc2xu2aazsDo6ca9f49hUIUqa70NbOI5Gb-YSyu1MLX4NxmD_5jMB8sBV-66QD0IUl-dzxcgPfIhkufvaoz0Tyiy4BnMrHbUNqaXFVBufb4bHMwJiZ1J-hzJ-kjK8eSaD4cUQaBGQre0ma3N4ZB-iZILKqoYBaF_cT2Tjk7dLlmL-XoNCVSNysTavromJ0FoMWwjkvXcoO_hoYBwxT-uQyK12aF-UuTIsg68lyt4gr8eLbIAgAK1Jm255cv1s52jxeOgDeSKUTwHH_MF8ICMTJefqXOTFKt7LCEKrmpyjysjKc6aSorJ17N8byAZcDlvCpa-uQv97Htg1m-sivIEE6ADfsvFgOECFOJ30VU_d94S3qFFdfNSIuUBfu0aRZRfA1x3b6xP5qa3yMpxIb0CinTItesHSsafwA6ZU_Pd9u1ndFX08jUIbdRWB2PJC02-sr9VItXmlHZcIJi2PT4VPJNCc8f5m2o4MoEBnuMmBOT8esIxpgiiMgEzCNgEVTjiRwwIgO3RqF2EuCWz6G1vL92QgIGFjrFFaMPj8cB8w5ppaT47zO4dW9F1LBKJ6YF-zsExZGmE0M1lJPk5XiBmjwI3iR1KCGSCtIdFmBPSZoTXvzFCMLI4jK2ank0cmq3NzTsaX4sqvGnAnRpzI-QemJ8MneLMMK9d2N-1gmXDA02ulylVdGZanitdWGStQm7aTnXyrQEewsa9ACx8DLNJrO0gx_he5WFwE1fxl9YxWda9WqcgnviiUHAupGFQdZ99psZtaEm-zAWtk8_Ak2B-QByTxmvqGPBj_c4CsRfllSkum3CSDK1-LeULScH_w5edkmwRRC66hq49fVnmJNjuu73rx7XUMunT38kLqBJ8mJvJ0BPj7cq8aiQTvDcFNKGTI8n8SsfYVJAPQmGB1DWy3z0c6e0Rx7om9SrFx8Lsz6rXX0cMZqM_xoGCrNfgweVyoKqPgykcDBCtjcXfRQd6_oasCRE2brr7HkHBiA--P0rPPTztPcjdMegpwBhdqFVm2U0UQtUXDxYg8GLVJSyZovlM8gR7NP2yFJ0xEmIC1xNGaT4kE66Zo87cL0gWkUfJPM6mGP9zuX4Y6vxE2q6pIcjdNHguMy1y6FZjbdzhrOu0G_Ze8KHInf0IaWmZZf6cFmUjjs_PFN398oSrqvPUuv5-bEaDFJXrAFrxjc38oMV2ZFszVfnVrNDm6Tw43NVCv2dpy2TIVuq07tH7Xvj3DEfe484bjMqt_6Z2eT4-RXxYZKuT8uEdxgHADa7voDE6vnsbBEZhqR9Lv6PNNeA1YO9aumhoaFsPwQ8B9m1xhWxNJO4pbToa__Xs8goxePNc2OZ3zRwmZeVE8iXyDsBvZATCpkI8UKWzlm9HGe9ukG9efWRzR0owf0XDC0eP2pKnYISUNxrzt-7wlI_vnih6IYH_UL6bNMEVECW9MRECpD0hMLVqnUTdpSSusFTGYXVhf4Zj5juET15chEOQWTtjR1PRRcI-ym-pnYjxutghRX-_tV7-kFQHehl6b4AqrA-9OI1LWUpnkvOiOTVpgWhXYzE4VAy7IJ-AaKHp0t1M1yKjeaZ7xmJ8PBz__iAFEDaqxHOE-7vkVY4Rs5NxrHZYzdf2m2ZcNSzyG4dhDdFYSWNv2GgYpfwekGmQcg39NRnLywAHVHikHTWxGf6-sxGtdbnIKiiFVDq4QMhcVblyeQjS4U3UiRG0VLyI8Rr3awv9vw25XPZhkS4A-LC4JYWs8FGt9EqM1ehFe9rmYX_ZxyvbZnkP9uBehXRUJ1KWb-vG0JbWEAzNgZaFT7QEKEtjmZ67kaSFKgxNDBQnqZJsCc1IB0lDjYO6M5s-dSN-lzYepvwehUHK84u1Yihu0bwQU8NX0x50NKENfYSAhVfJmFPxHoKHH9bPJYR3LGIfA6oLiSs-uAPAk_Ykov-W0E4MVU8H18Pa3AQffVb17yGUREhiFPxF4zJ_K-3rj476bWxYRP--Rey-vrQFLpKk6XrttPgKY-3i7bfDDNnzuBrddm4F3GwJ23cGzXwE2aTE2IgrZI83iOSOPQWuCGDcpPTbfk5MDkWR-Y84MUD0tvwzEUXEK5EiPefSV0RsX7HBXGLDBpx6u1b-w9ktCHF3Km-ATMR9I19Prb6L6uZQxm5cvsc-v2nI0dVjkSW8lpLJa4Ohg17WBUMAWpxftfaBV2ZCxEXq5cb7MUmajHWEs3azHbVsffZV0b4LO62mNqDG6Hai6ZaFi5v4QYKo7ha-KIq8APiw32kE6IXWXcTmVX2-Y3AnFqYgiZdbnOiR7PdcH28EV2ardByrgER4yX7mU5WFxkrp2JzReSm6NQUOQbh8zwPhMBCHRJvpB7tl1IhrwNHAHwGQl-J6H4kkqsag4tL4Lacpw_g6iXlK2EZx_cPJ__5CAmXFEH1TCUkdY2OccdVzd2VUysiR4iDGEs-Uvp0IYI05KPnpc8gtJYAMHHR85dO4qy2s93JqX6Rfra_JNzh0fD2gYA9JFnuo1SOXtwFZozp7VerBIlpkAxUV8D0hhaN3OjCHQBybStCaf_14rG8MZQqvO1REU6G8mwNVsGHhKAjWh1fK1G0qBZZodw54sfbzO8DaXO2Jjc3XDtr8vvSvCALyuxvIgaf9Fgtfs3IBjKhxDg-6R7ZRZIHsWIhxO3ZHdJ58Hc9BAHGNjNXuhS7Rt0dmodlwUVsK2jhkr15adF3ZCndL12-2kIPWAeAJ319BrqPuhkCVmD3pNFgkLRDm7izGqE9sOskkwU9kNUbJf8SEnNQAZr9l4oyIiMVXQ9v6Fhm7sB7-RUWP7DwqEyxs4-9_kY6S90Bm2NejJGKI5Ow-lCIQj2mYSVSPD1RGskW1LHEmoVAPwOLgj1-7FugqvOkXPRLHPbmZOxbMlkUI-pbEusuwXb_oBQBHZLemqC_kU4JtCnRfDAxMwtYQB9ful7goq79OrmbuXZwok81XXNSK69O3G2lYLJdxEgaE2ibwaYygg_cn4jkYGAwFPCxH-cTNszVzMX789LKTIfLswKDdgg0deyesAF6eSCRyuzY12edG_5w5wignfS-nYTPCTOJcQmsAduiKyXQsvBdJM7tTLWXIXJy2dZt5HpTLW6_ALOj3HcATLH8hxeYmJBiw02FazG_2FXiEoVtOAZ_n0I4qm8wKc5-4t215xrzmjD2ZchViImob-TzKvxpMJpHHXKjTv2Urk1FtZ_yPV7yA6zstLZmaWE48UAZk6GXUo9p2Gi5MprpzxaQbq74YLXgIRULhEKsdCKWQ-s6JA0LjUSoQW60zucdW6BSf432QlgmnRMdKiCk2V4GwoeTbIxOrqjQedWOk8XzA9-yd7KRyZZyjxQAb5vVu2AAAAAQAAAAxsVJu4NY7cRmRJgKr3lZ9TVbiqGecLdKLTTCbnNzIOxw"));
            }
        }

        let dc_verification_result = derived_vc
            .verify(
                Some(verify_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        assert!(!dc_verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn credential_issue_verify_bs58() {
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

        let key_str = include_str!("../../tests/ed25519-2020-10-18.json");
        let key: JWK = serde_json::from_str(key_str).unwrap();

        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String("did:example:foo#key3".to_string())),
            ..Default::default()
        };
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
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
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(!verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn credential_issue_verify_no_z() {
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-19T21:41:50+00:00",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
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

        let issue_options = LinkedDataProofOptions {
            proof_purpose: Some(ProofPurpose::AssertionMethod),
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let algorithm = key.get_algorithm().unwrap();
        let public_key = key.to_public();

        let preparation = vc
            .prepare_proof(
                &public_key,
                &issue_options,
                &DIDExample,
                &mut context_loader,
            )
            .await
            .unwrap();
        let signing_input = match preparation.signing_input {
            ssi_ldp::SigningInput::Bytes(ref bytes) => &bytes.0,
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected signing input type"),
        };
        let sig = ssi_jws::sign_bytes(algorithm, signing_input, &key).unwrap();
        let sig_b64 = base64::encode_config(sig, base64::URL_SAFE_NO_PAD);
        let proof = preparation
            .proof
            .type_
            .complete(&preparation, &sig_b64)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
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
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(!verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn proof_json_to_urdna2015() {
        use serde_json::json;
        let proof_str = r###"{
            "type": "RsaSignature2018",
            "created": "2020-09-03T15:15:39Z",
            "verificationMethod": "https://example.org/foo/1",
            "proofPurpose": "assertionMethod"
        }"###;
        let urdna2015_expected = r###"_:c14n0 <http://purl.org/dc/terms/created> "2020-09-03T15:15:39Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#RsaSignature2018> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <https://example.org/foo/1> .
"###;
        let proof: Proof = serde_json::from_str(proof_str).unwrap();
        struct ProofContexts(Value);
        #[async_trait]
        impl LinkedDataDocument for ProofContexts {
            fn get_contexts(&self) -> Result<Option<String>, ssi_ldp::Error> {
                Ok(Some(serde_json::to_string(&self.0)?))
            }

            async fn to_dataset_for_signing(
                &self,
                _parent: Option<&(dyn LinkedDataDocument + Sync)>,
                _context_loader: &mut ContextLoader,
            ) -> Result<DataSet, ssi_ldp::Error> {
                Err(ssi_ldp::Error::MissingAlgorithm)
            }

            fn to_value(&self) -> Result<Value, ssi_ldp::Error> {
                Ok(self.0.clone())
            }
        }
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let parent = ProofContexts(json!(["https://w3id.org/security/v1", DEFAULT_CONTEXT]));
        let proof_dataset = proof
            .to_dataset_for_signing(Some(&parent), &mut context_loader)
            .await
            .unwrap();
        let proof_dataset_normalized = urdna2015::normalize(proof_dataset.quads().map(Into::into));
        let proof_urdna2015 = proof_dataset_normalized.into_nquads();
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
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let credential_dataset = vc
            .to_dataset_for_signing(None, &mut context_loader)
            .await
            .unwrap();
        let credential_dataset_normalized =
            urdna2015::normalize(credential_dataset.quads().map(Into::into));
        let credential_urdna2015 = credential_dataset_normalized.into_nquads();
        eprintln!("credential:\n{}", credential_urdna2015);
        eprintln!("expected:\n{}", urdna2015_expected);
        assert_eq!(credential_urdna2015, urdna2015_expected);
    }

    #[async_std::test]
    async fn credential_verify() {
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        good_vc(
            include_str!("../../examples/vc.jsonld"),
            &mut context_loader,
        )
        .await;

        let vc_jwt = include_str!("../../examples/vc.jwt");
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let (vc_opt, result) =
            Credential::decode_verify_jwt(vc_jwt, None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", result);
        let vc = vc_opt.unwrap();
        println!("{:#?}", vc);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    async fn good_vc(vc_str: &str, context_loader: &mut ContextLoader) {
        let vc = Credential::from_json(vc_str).unwrap();
        let result = vc.verify(None, &DIDExample, context_loader).await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    async fn bad_vc(vc_str: &str, context_loader: &mut ContextLoader) {
        let vc = match Credential::from_json(vc_str) {
            Ok(vc) => vc,
            Err(_) => return,
        };
        let result = vc.verify(None, &DIDExample, context_loader).await;
        println!("{:#?}", result);
        assert!(!result.errors.is_empty());
    }

    #[async_std::test]
    async fn credential_verify_proof_consistency() {
        // These test vectors were generated using examples/issue.rs with the verify part disabled,
        // and with changes made to contexts/lds-jws2020-v1.jsonld, and then copying the context
        // object into the VC.
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        good_vc(
            include_str!("../../examples/vc-jws2020-inline-context.jsonld"),
            &mut context_loader,
        )
        .await;
        bad_vc(
            include_str!("../../examples/vc-jws2020-bad-type.jsonld"),
            &mut context_loader,
        )
        .await;
        bad_vc(
            include_str!("../../examples/vc-jws2020-bad-purpose.jsonld"),
            &mut context_loader,
        )
        .await;
        bad_vc(
            include_str!("../../examples/vc-jws2020-bad-method.jsonld"),
            &mut context_loader,
        )
        .await;
        bad_vc(
            include_str!("../../examples/vc-jws2020-bad-type-json.jsonld"),
            &mut context_loader,
        )
        .await;
        bad_vc(
            include_str!("../../examples/vc-jws2020-bad-purpose-json.jsonld"),
            &mut context_loader,
        )
        .await;
        bad_vc(
            include_str!("../../examples/vc-jws2020-bad-method-json.jsonld"),
            &mut context_loader,
        )
        .await;
    }

    #[async_std::test]
    async fn cannot_add_properties_after_signing() {
        use serde_json::json;
        let vc_str = include_str!("../../examples/vc.jsonld");
        let mut vc: Value = serde_json::from_str(vc_str).unwrap();
        vc["newProp"] = json!("foo");
        let vc: Credential = serde_json::from_value(vc).unwrap();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", result);
        assert!(!result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[async_std::test]
    async fn presentation_verify() {
        // LDP VC in LDP VP
        let vp_str = include_str!("../../examples/vp.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();
        let verify_options = LinkedDataProofOptions {
            proof_purpose: Some(ProofPurpose::Authentication),
            ..Default::default()
        };
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let result = vp
            .verify(
                Some(verify_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vc = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::Credential(vc)) => vc,
            _ => unreachable!(),
        };
        let result = vc.verify(None, &DIDExample, &mut context_loader).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());

        // LDP VC in JWT VP
        let vp_jwt = include_str!("../../examples/vp.jwt");
        let (vp_opt, result) = Presentation::decode_verify_jwt(
            vp_jwt,
            Some(verify_options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vp = vp_opt.unwrap();
        let vc = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::Credential(vc)) => vc,
            _ => unreachable!(),
        };
        let result = vc.verify(None, &DIDExample, &mut context_loader).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());

        // JWT VC in LDP VP
        let vp_str = include_str!("../../examples/vp-jwtvc.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();
        let result = vp
            .verify(
                Some(verify_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vc_jwt = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::JWT(jwt)) => jwt,
            _ => unreachable!(),
        };
        let result = Credential::verify_jwt(&vc_jwt, None, &DIDExample, &mut context_loader).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());

        // JWT VC in JWT VP
        let vp_jwt = include_str!("../../examples/vp-jwtvc.jwt");
        let (vp_opt, result) = Presentation::decode_verify_jwt(
            vp_jwt,
            Some(verify_options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", result);
        let vp = vp_opt.unwrap();

        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vc_jwt = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::JWT(jwt)) => jwt,
            _ => unreachable!(),
        };
        let result = Credential::verify_jwt(&vc_jwt, None, &DIDExample, &mut context_loader).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[async_std::test]
    async fn credential_status() {
        use serde_json::json;
        let mut unrevoked_vc: Credential = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc-revocation-list-2020/v1"
            ],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2021-08-25T18:38:54Z",
            "credentialSubject": {
              "id": "did:example:foo"
            },
            "credentialStatus": {
                "id": "_:1",
                "type": "RevocationList2020Status",
                "revocationListCredential": EXAMPLE_REVOCATION_2020_LIST_URL,
                "revocationListIndex": "0"
            }
        }))
        .unwrap();
        let mut revoked_vc: Credential = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc-revocation-list-2020/v1"
            ],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2021-08-25T20:15:45Z",
            "credentialSubject": {
              "id": "did:example:foo"
            },
            "credentialStatus": {
                "id": "_:1",
                "type": "RevocationList2020Status",
                "revocationListCredential": EXAMPLE_REVOCATION_2020_LIST_URL,
                "revocationListIndex": "1"
            }
        }))
        .unwrap();
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String("did:example:foo#key1".to_string())),
            ..Default::default()
        };
        let verify_options = LinkedDataProofOptions {
            checks: Some(vec![Check::Proof, Check::Status]),
            ..Default::default()
        };

        let mut context_loader = ssi_json_ld::ContextLoader::default();
        // Issue unrevoked VC
        let proof = unrevoked_vc
            .generate_proof(&key, &issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        unrevoked_vc.add_proof(proof);
        unrevoked_vc.validate().unwrap();

        // Issue revoked VC
        let proof = revoked_vc
            .generate_proof(&key, &issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        revoked_vc.add_proof(proof);
        revoked_vc.validate().unwrap();

        // Verify unrevoked VC
        let verification_result = unrevoked_vc
            .verify(
                Some(verify_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        println!("{:#?}", verification_result);
        assert_eq!(verification_result.errors.len(), 0);

        // Verify revoked VC
        let verification_result = revoked_vc
            .verify(Some(verify_options), &DIDExample, &mut context_loader)
            .await;
        println!("{:#?}", verification_result);
        assert_ne!(verification_result.errors.len(), 0);
    }

    #[async_std::test]
    async fn credential_status_2021() {
        use serde_json::json;
        // status list credential is generated in examples/issue-status-list.rs

        // based on https://w3c-ccg.github.io/vc-status-list-2021/#example-example-statuslist2021credential
        let unrevoked_credential: Credential = serde_json::from_value(json!({
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc/status-list/2021/v1"
          ],
          "id": "https://example.com/credentials/23894672394",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:12345",
          "issued": "2021-04-05T14:27:42Z",
          "credentialStatus": {
            "id": "_:1",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "94567",
            "statusListCredential": EXAMPLE_STATUS_LIST_2021_URL
          },
          "credentialSubject": {
            "id": "did:example:6789",
            "type": "Person"
          }
        }))
        .unwrap();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vres = unrevoked_credential
            .check_status(&DIDExample, &mut context_loader)
            .await;
        println!("{:#?}", vres);
        assert_eq!(vres.errors.len(), 0);

        let revoked_credential: Credential = serde_json::from_value(json!({
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc/status-list/2021/v1"
          ],
          "id": "https://example.com/credentials/23894672394",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:12345",
          "issued": "2021-04-05T14:27:42Z",
          "credentialStatus": {
            "id": "_:1",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "1",
            "statusListCredential": EXAMPLE_STATUS_LIST_2021_URL
          },
          "credentialSubject": {
            "id": "did:example:6789",
            "type": "Person"
          }
        }))
        .unwrap();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vres = revoked_credential
            .check_status(&DIDExample, &mut context_loader)
            .await;
        println!("{:#?}", vres);
        assert_ne!(vres.errors.len(), 0);
    }

    #[async_std::test]
    async fn interop_jwt_vc() {
        use time::{
            ext::NumericalDuration, format_description::well_known::Rfc3339, OffsetDateTime,
        };
        let vc = json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:placeholder",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "expirationDate": (OffsetDateTime::now_utc() + (52*10).weeks()).replace_nanosecond(0).unwrap().format(&Rfc3339).unwrap(),
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        });
        let mut vc: Credential = serde_json::from_value(vc).unwrap();
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
        let mut vc_issue_options = LinkedDataProofOptions::default();
        let vc_issuer_key = "did:example:foo".to_string();
        let vc_issuer_vm = "did:example:foo#key1".to_string();
        vc.issuer = Some(Issuer::URI(URI::String(vc_issuer_key.to_string())));
        vc_issue_options.verification_method = Some(URI::String(vc_issuer_vm));
        vc_issue_options.proof_purpose = Some(ProofPurpose::AssertionMethod);
        vc_issue_options.checks = None;
        vc_issue_options.created = None;
        let vc_jwt = vc
            .generate_jwt(Some(&key), &vc_issue_options, &DIDExample)
            .await
            .unwrap();
        let verifier = josekit::jws::PS256
            .verifier_from_jwk(&josekit::jwk::Jwk::from_bytes(JWK_JSON).unwrap())
            .unwrap();
        josekit::jwt::decode_with_verifier(vc_jwt, &verifier).unwrap();
    }

    #[async_std::test]
    async fn verify_old_jwt_vc_decimal_timestamp() {
        let vc_jwt = "eyJhbGciOiJQUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmZvbyNrZXkxIn0.eyJleHAiOjE5OTUyNjczOTcuMTI1ODg4LCJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJuYmYiOjE1OTc4NzMzMTAuMCwianRpIjoiaHR0cDovL2V4YW1wbGUub3JnL2NyZWRlbnRpYWxzLzM3MzEiLCJzdWIiOiJkaWQ6ZXhhbXBsZTpkMjNkZDY4N2E3ZGM2Nzg3NjQ2ZjJlYjk4ZDAiLCJ2YyI6eyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaWQiOiJodHRwOi8vZXhhbXBsZS5vcmcvY3JlZGVudGlhbHMvMzczMSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTpkMjNkZDY4N2E3ZGM2Nzg3NjQ2ZjJlYjk4ZDAifSwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6Zm9vIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0wOC0xOVQyMTo0MTo1MFoiLCJleHBpcmF0aW9uRGF0ZSI6IjIwMzMtMDMtMjRUMDg6NTY6MzcuMTI1ODg4WiJ9fQ.qCOIRr090plGC2SYQeTMuasErurjGeCbHNjkfospByWHxadk-8oz6P6beH03Adafu0I-7xrpEIxmC-KfHynAuEBCpjHMYh0rY2nGHX1sH530DE9O1FOK2IXtvScPKLzCv6v25qIUydzJZY9MnuoO879iowDgMgSAkDzjl8ZXnKpG3_dvoATrVpjP4FeC5m2JVJTMnOIKfehy9ZeFzilb9VcGmprWGWB_e2BJJ_wnLfxorVbGmS7QvTsARuUn_jPxrq_JPf9UZqwGb_wMwN7KG1VJRBuGix9ltf-KNwXI-Qm-9ZabYHub9n0Q3AHTDO78Lr4Or1PuiGq-QNQLtSVb5Q";
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vc_verification_result =
            Credential::verify_jwt(vc_jwt, None, &DIDExample, &mut context_loader).await;
        assert!(vc_verification_result.errors.is_empty());
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
        vc_issue_options.verification_method = Some(URI::String(vc_issuer_vm));
        vc_issue_options.proof_purpose = Some(ProofPurpose::AssertionMethod);
        vc_issue_options.checks = None;
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vc_proof = vc
            .generate_proof(&key, &vc_issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        vc.add_proof(vc_proof);
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        vc.validate().unwrap();
        let vc_verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", vc_verification_result);
        assert!(vc_verification_result.errors.is_empty());

        // Issue JWT credential
        vc_issue_options.created = None;
        let vc_jwt = vc
            .generate_jwt(Some(&key), &vc_issue_options, &DIDExample)
            .await
            .unwrap();
        let vc_verification_result =
            Credential::verify_jwt(&vc_jwt, None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", vc_verification_result);
        assert!(vc_verification_result.errors.is_empty());

        // Issue Presentation with Credential
        let mut vp = Presentation {
            context: Contexts::Many(vec![Context::URI(URI::String(DEFAULT_CONTEXT.to_string()))]),
            id: Some("http://example.org/presentations/3731".try_into().unwrap()),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: Some(URI::String("did:example:foo".to_string())),
            holder_binding: None,
            property_set: None,
        };
        let vp_without_proof = vp.clone();
        let mut vp_issue_options = LinkedDataProofOptions::default();
        let vp_issuer_key = "did:example:foo#key1".to_string();
        vp_issue_options.verification_method = Some(URI::String(vp_issuer_key));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        vp_issue_options.checks = None;
        let vp_proof = vp
            .generate_proof(&key, &vp_issue_options, &DIDExample, &mut context_loader)
            .await
            .unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp
            .verify(
                Some(vp_issue_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
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
        let vp_verification_result = vp1
            .verify(
                Some(vp_issue_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(!vp_verification_result.errors.is_empty());

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(!vp2
            .verify(None, &DIDExample, &mut context_loader)
            .await
            .errors
            .is_empty());

        // Test JWT VP
        let vp_jwt_issue_options = LinkedDataProofOptions {
            created: None,
            ..vp_issue_options.clone()
        };
        let vp_jwt = vp_without_proof
            .generate_jwt(Some(&key), &vp_jwt_issue_options.clone(), &DIDExample)
            .await
            .unwrap();
        let vp_jwt_verify_options = LinkedDataProofOptions {
            checks: None,
            proof_purpose: None,
            ..Default::default()
        };
        let verification_result = Presentation::verify_jwt(
            &vp_jwt,
            Some(vp_jwt_verify_options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
        // Edit JWT to make it fail
        let vp_jwt_bad = vp_jwt + "x";
        let verification_result = Presentation::verify_jwt(
            &vp_jwt_bad,
            Some(vp_jwt_verify_options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        assert!(!verification_result.errors.is_empty());

        // Test VP with JWT VC
        let vp_jwtvc = Presentation {
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::JWT(vc_jwt))),
            holder: Some(URI::String("did:example:foo".to_string())),
            ..Default::default()
        };

        // LDP VP
        let proof = vp_jwtvc
            .generate_proof(
                &key,
                &vp_issue_options.clone(),
                &DIDExample,
                &mut context_loader,
            )
            .await
            .unwrap();
        let mut vp_jwtvc_ldp = vp_jwtvc.clone();
        vp_jwtvc_ldp.add_proof(proof);
        let vp_verify_options = vp_issue_options.clone();
        let verification_result = vp_jwtvc_ldp
            .verify(
                Some(vp_verify_options.clone()),
                &DIDExample,
                &mut context_loader,
            )
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // JWT VP
        let vp_vc_jwt = vp_jwtvc
            .generate_jwt(Some(&key), &vp_jwt_issue_options.clone(), &DIDExample)
            .await
            .unwrap();
        let verification_result = Presentation::verify_jwt(
            &vp_vc_jwt,
            Some(vp_jwt_verify_options.clone()),
            &DIDExample,
            &mut context_loader,
        )
        .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[async_std::test]
    async fn present_with_example_holder_binding() {
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let key: JWK = serde_json::from_str(JWK_JSON_BAR).unwrap();
        let mut vp_issue_options = LinkedDataProofOptions::default();
        let vp_proof_vm = "did:example:bar#key1".to_string();
        vp_issue_options.verification_method = Some(URI::String(vp_proof_vm));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        vp_issue_options.checks = None;

        {
            let mut vp: Presentation = serde_json::from_value(serde_json::json!({
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    {
                        "@vocab": "https://example.org/example-holder-binding#"
                    }
                ],
                "type": ["VerifiablePresentation"],
                "holderBinding": {
                    "type": "ExampleHolderBinding2022",
                    "from": "did:example:foo",
                    "to": "did:example:bar",
                    "proof": "..."
                },
                "holder": "did:example:bar"
            }))
            .unwrap();

            let vp_proof = vp
                .generate_proof(&key, &vp_issue_options, &DIDExample, &mut context_loader)
                .await
                .unwrap();
            vp.add_proof(vp_proof);
            println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
            // Verify VP
            vp.validate().unwrap();
            let vp_verification_result = vp.verify(None, &DIDExample, &mut context_loader).await;
            println!("{:#?}", vp_verification_result);
            assert!(vp_verification_result.errors.is_empty());
        }

        {
            // Do the same thing but with a mismatched holder binding
            // Verify VP fails
            let mut vp: Presentation = serde_json::from_value(serde_json::json!({
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    {
                        "@vocab": "https://example.org/example-holder-binding#"
                    }
                ],
                "type": ["VerifiablePresentation"],
                "holderBinding": {
                    "type": "ExampleHolderBinding2022",
                    "from": "did:example:foo",
                    "to": "did:example:foo",
                    "proof": "..."
                },
                "holder": "did:example:bar"
            }))
            .unwrap();
            let vp_proof = vp
                .generate_proof(&key, &vp_issue_options, &DIDExample, &mut context_loader)
                .await
                .unwrap();
            vp.add_proof(vp_proof);
            let vp_verification_result = vp.verify(None, &DIDExample, &mut context_loader).await;
            println!("{:#?}", vp_verification_result);
            assert!(!vp_verification_result.errors.is_empty());
        }

        {
            // Check that verifying a VP with an unknown holder binding type produces an error.
            let mut vp: Presentation = serde_json::from_value(serde_json::json!({
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    {
                        "@vocab": "https://example.org/example-holder-binding#"
                    }
                ],
                "type": ["VerifiablePresentation"],
                "holderBinding": {
                    "type": "SomeOtherThing",
                    "field": "something"
                },
                "holder": "did:example:bar"
            }))
            .unwrap();
            let vp_proof = vp
                .generate_proof(&key, &vp_issue_options, &DIDExample, &mut context_loader)
                .await
                .unwrap();
            vp.add_proof(vp_proof);
            let vp_verification_result = vp.verify(None, &DIDExample, &mut context_loader).await;
            println!("{:#?}", vp_verification_result);
            assert!(!vp_verification_result.errors.is_empty());
        }
    }

    #[async_std::test]
    async fn esrs2020() {
        use ssi_dids::did_resolve::{
            DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
            TYPE_DID_LD_JSON,
        };
        use ssi_dids::Document;

        struct ExampleResolver;

        const EXAMPLE_123_ID: &str = "did:example:123";
        const EXAMPLE_123_JSON: &str = include_str!("../../tests/esrs2020-did.jsonld");

        #[async_trait]
        impl DIDResolver for ExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                if did == EXAMPLE_123_ID {
                    let doc = match Document::from_json(EXAMPLE_123_JSON) {
                        Ok(doc) => doc,
                        Err(err) => {
                            return (
                                ResolutionMetadata::from_error(&format!("JSON Error: {:?}", err)),
                                None,
                                None,
                            );
                        }
                    };
                    (
                        ResolutionMetadata {
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
                }
            }

            async fn resolve_representation(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
                if did == EXAMPLE_123_ID {
                    let vec = EXAMPLE_123_JSON.as_bytes().to_vec();
                    (
                        ResolutionMetadata {
                            error: None,
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            property_set: None,
                        },
                        vec,
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (
                        ResolutionMetadata::from_error(ERROR_NOT_FOUND),
                        Vec::new(),
                        None,
                    )
                }
            }
        }

        let vc_str = include_str!("../../tests/esrs2020-vc.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let mut n_proofs = 0;
        for proof in vc.proof.iter().flatten() {
            n_proofs += 1;
            let resolver = ExampleResolver;
            let mut context_loader = ssi_json_ld::ContextLoader::default();
            let warnings = ProofSuiteType::EcdsaSecp256k1RecoverySignature2020
                .verify(proof, &vc, &resolver, &mut context_loader, None, None)
                .await
                .unwrap();
            assert!(warnings.is_empty());
        }
        assert_eq!(n_proofs, 4);
    }

    #[async_std::test]
    async fn ed2020() {
        // https://w3c-ccg.github.io/lds-ed25519-2020/#example-4
        let vmm: VerificationMethodMap = serde_json::from_value(serde_json::json!({
          "id": "https://example.com/issuer/123#key-0",
          "type": "Ed25519KeyPair2020",
          "controller": "https://example.com/issuer/123",
          "publicKeyMultibase": "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
          "privateKeyMultibase": "zrv3kJcnBP1RpYmvNZ9jcYpKBZg41iSobWxSg3ix2U7Cp59kjwQFCT4SZTgLSL3HP8iGMdJs3nedjqYgNn6ZJmsmjRm"
        }))
        .unwrap();

        let sk_hex = "9b937b81322d816cfab9d5a3baacc9b2a5febe4b149f126b3630f93a29527017095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let sk_bytes_mc = [vec![0x80, 0x26], sk_bytes.clone()].concat();
        let sk_mb = multibase::encode(multibase::Base::Base58Btc, &sk_bytes_mc);
        let props = &vmm.property_set.unwrap();
        let sk_mb_expected = props
            .get("privateKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(&sk_mb, &sk_mb_expected);

        let pk_hex = "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let pk_bytes_mc = [vec![0xed, 0x01], pk_bytes.clone()].concat();
        let pk_mb = multibase::encode(multibase::Base::Base58Btc, &pk_bytes_mc);
        let pk_mb_expected = props
            .get("publicKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(&pk_mb, &pk_mb_expected);

        assert_eq!(&sk_bytes[32..64], &pk_bytes);

        let is = include_str!("../../tests/lds-ed25519-2020-issuer0.jsonld");
        // let vv: ssi_dids::VerificationMethod =
        //     serde_json::from_str("https://example.com/issuer/123#key-0").unwrap();
        // println!("{:?}", vv);
        let issuer_document: Document = serde_json::from_str(is).unwrap();

        let vc_str = include_str!("../../tests/lds-ed25519-2020-vc0.jsonld");
        let vc = Credential::from_json(vc_str).unwrap();
        let vp_str = include_str!("../../tests/lds-ed25519-2020-vp0.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();

        // "DID Resolver" for HTTPS issuer used in the test vectors.
        struct ED2020ExampleResolver {
            issuer_document: Document,
        }
        use ssi_dids::did_resolve::{
            Content, ContentMetadata, DereferencingMetadata, DocumentMetadata,
            ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
        };
        use ssi_dids::{Document, PrimaryDIDURL};
        use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params as JWKParams};
        use ssi_ldp::{ProofSuite, ProofSuiteType};
        #[async_trait]
        impl DIDResolver for ED2020ExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                // Return empty result here to allow DID URL dereferencing to proceed. The DID
                // is resolved as part of DID URL dereferencing, but the DID document is not used.
                if did == "https:" {
                    let doc_meta = DocumentMetadata::default();
                    let doc = Document::new(did);
                    return (ResolutionMetadata::default(), Some(doc), Some(doc_meta));
                }
                (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
            }

            async fn dereference(
                &self,
                did_url: &PrimaryDIDURL,
                _input_metadata: &DereferencingInputMetadata,
            ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
                match &did_url.to_string()[..] {
                    "https://example.com/issuer/123" => Some((
                        DereferencingMetadata {
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            ..Default::default()
                        },
                        Content::DIDDocument(self.issuer_document.clone()),
                        ContentMetadata::default(),
                    )),
                    _ => None,
                }
            }
        }

        let sk_jwk = JWK::from(JWKParams::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(sk_bytes[32..64].to_vec()),
            private_key: Some(Base64urlUInt(sk_bytes[0..32].to_vec())),
        }));
        assert_eq!(sk_bytes.len(), 64);
        eprintln!("{}", serde_json::to_string(&sk_jwk).unwrap());

        let issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(
                "https://example.com/issuer/123#key-0".to_string(),
            )),
            proof_purpose: Some(ProofPurpose::AssertionMethod),
            created: Some(Utc::now().with_nanosecond(0).unwrap()),
            ..Default::default()
        };

        let resolver = ED2020ExampleResolver { issuer_document };
        let mut context_loader = ssi_json_ld::ContextLoader::default();

        println!("{}", serde_json::to_string(&vc).unwrap());
        // reissue VC
        let new_proof = ProofSuiteType::Ed25519Signature2020
            .sign(
                &vc,
                &issue_options,
                &resolver,
                &mut context_loader,
                &sk_jwk,
                None,
            )
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&new_proof).unwrap());

        // check new VC proof and original proof
        ProofSuiteType::Ed25519Signature2020
            .verify(&new_proof, &vc, &resolver, &mut context_loader, None, None)
            .await
            .unwrap();
        let orig_proof = vc.proof.iter().flatten().next().unwrap();
        ProofSuiteType::Ed25519Signature2020
            .verify(orig_proof, &vc, &resolver, &mut context_loader, None, None)
            .await
            .unwrap();

        // re-generate VP proof
        let vp_issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(
                "https://example.com/issuer/123#key-0".to_string(),
            )),
            proof_purpose: Some(ProofPurpose::Authentication),
            created: Some(Utc::now().with_nanosecond(0).unwrap()),
            challenge: Some("123".to_string()),
            ..Default::default()
        };
        let new_proof = ProofSuiteType::Ed25519Signature2020
            .sign(
                &vp,
                &vp_issue_options,
                &resolver,
                &mut context_loader,
                &sk_jwk,
                None,
            )
            .await
            .unwrap();
        println!("{}", serde_json::to_string(&new_proof).unwrap());

        // check new VP proof and original proof
        ProofSuiteType::Ed25519Signature2020
            .verify(&new_proof, &vp, &resolver, &mut context_loader, None, None)
            .await
            .unwrap();
        let orig_proof = vp.proof.iter().flatten().next().unwrap();
        ProofSuiteType::Ed25519Signature2020
            .verify(orig_proof, &vp, &resolver, &mut context_loader, None, None)
            .await
            .unwrap();

        // Try using prepare/complete
        let pk_jwk = sk_jwk.to_public();
        let prep = ProofSuiteType::Ed25519Signature2020
            .prepare(
                &vp,
                &vp_issue_options,
                &resolver,
                &mut context_loader,
                &pk_jwk,
                None,
            )
            .await
            .unwrap();
        let signing_input_bytes = match prep.signing_input {
            ssi_ldp::SigningInput::Bytes(Base64urlUInt(ref bytes)) => bytes,
            _ => panic!("expected SigningInput::Bytes for Ed25519Signature2020 preparation"),
        };
        let sig = ssi_jws::sign_bytes(Algorithm::EdDSA, signing_input_bytes, &sk_jwk).unwrap();
        let sig_mb = multibase::encode(multibase::Base::Base58Btc, sig);
        let completed_proof = ProofSuiteType::Ed25519Signature2020
            .complete(&prep, &sig_mb)
            .await
            .unwrap();
        ProofSuiteType::Ed25519Signature2020
            .verify(
                &completed_proof,
                &vp,
                &resolver,
                &mut context_loader,
                None,
                None,
            )
            .await
            .unwrap();
    }

    #[async_std::test]
    async fn aleosig2021() {
        use crate::Credential;
        use ssi_dids::did_resolve::{
            DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
            TYPE_DID_LD_JSON,
        };
        use ssi_dids::Document;

        struct ExampleResolver;
        const EXAMPLE_DID: &str = "did:example:aleovm2021";
        const EXAMPLE_DOC: &str = include_str!("../../tests/lds-aleo2021-issuer0.jsonld");
        #[async_trait]
        impl DIDResolver for ExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                if did == EXAMPLE_DID {
                    let doc = match Document::from_json(EXAMPLE_DOC) {
                        Ok(doc) => doc,
                        Err(err) => {
                            return (
                                ResolutionMetadata::from_error(&format!("JSON Error: {:?}", err)),
                                None,
                                None,
                            );
                        }
                    };
                    (
                        ResolutionMetadata {
                            content_type: Some(TYPE_DID_LD_JSON.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
                }
            }
        }

        let private_key: JWK =
            serde_json::from_str(include_str!("../../tests/aleotestnet1-2021-11-22.json")).unwrap();

        let vc_str = include_str!("../../tests/lds-aleo2021-vc0.jsonld");
        let mut vc = Credential::from_json_unsigned(vc_str).unwrap();
        let resolver = ExampleResolver;
        let mut context_loader = ssi_json_ld::ContextLoader::default();

        if vc.proof.iter().flatten().next().is_none() {
            // Issue VC / Generate Test Vector
            let mut credential = vc.clone();
            let vc_issue_options = LinkedDataProofOptions {
                verification_method: Some(URI::String("did:example:aleovm2021#id".to_string())),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                ..Default::default()
            };
            let proof = ProofSuiteType::AleoSignature2021
                .sign(
                    &vc,
                    &vc_issue_options,
                    &resolver,
                    &mut context_loader,
                    &private_key,
                    None,
                )
                .await
                .unwrap();
            credential.add_proof(proof);
            vc = credential;

            use std::fs::File;
            use std::io::{BufWriter, Write};
            let outfile = File::create("tests/lds-aleo2021-vc0.jsonld").unwrap();
            let mut output_writer = BufWriter::new(outfile);
            serde_json::to_writer_pretty(&mut output_writer, &vc).unwrap();
            output_writer.write_all(b"\n").unwrap();
        }

        // Verify VC
        let proof = vc.proof.iter().flatten().next().unwrap();
        let warnings = ProofSuiteType::AleoSignature2021
            .verify(proof, &vc, &resolver, &mut context_loader, None, None)
            .await
            .unwrap();
        assert!(warnings.is_empty());
    }

    #[async_std::test]
    async fn verify_typed_data() {
        use sha3::Digest;
        use ssi_ldp::eip712::TypedData;
        let proof: Proof = serde_json::from_value(json!({
          "verificationMethod": "did:example:aaaabbbb#issuerKey-1",
          "created": "2021-07-09T19:47:41Z",
          "proofPurpose": "assertionMethod",
          "type": "EthereumEip712Signature2021",
          "eip712": {
            "types": {
              "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "salt", "type": "bytes32" }
              ],
              "VerifiableCredential": [
                { "name": "@context", "type": "string[]" },
                { "name": "type", "type": "string[]" },
                { "name": "id", "type": "string" },
                { "name": "issuer", "type": "string" },
                { "name": "issuanceDate", "type": "string" },
                { "name": "credentialSubject", "type": "CredentialSubject" },
                { "name": "credentialSchema", "type": "CredentialSchema" },
                { "name": "proof", "type": "Proof" }
              ],
              "CredentialSchema": [
                { "name": "id", "type": "string" },
                { "name": "type", "type": "string" }
              ],
              "CredentialSubject": [
                { "name": "type", "type": "string" },
                { "name": "id", "type": "string" },
                { "name": "name", "type": "string" },
                { "name": "child", "type": "Person" }
              ],
              "Person": [
                { "name": "type", "type": "string" },
                { "name": "name", "type": "string" }
              ],
              "Proof": [
                { "name": "verificationMethod", "type": "string" },
                { "name": "created", "type": "string" },
                { "name": "proofPurpose", "type": "string" },
                { "name": "type", "type": "string" }
              ]
            },
            "primaryType": "VerifiableCredential",
            "domain": {
              "name": "https://example.com",
              "version": "2",
              "chainId": 4,
              "salt": "0x000000000000000000000000000000000000000000000000aaaabbbbccccdddd"
            }
          }
        }))
        .unwrap();
        let vc: Credential = serde_json::from_value(json!({
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org"
          ],
          "type": [
            "VerifiableCredential"
          ],
          "id": "https://example.org/person/1234",
          "issuer": "did:example:aaaabbbb",
          "issuanceDate": "2010-01-01T19:23:24Z",
          "credentialSubject": {
            "type": "Person",
            "id": "did:example:bbbbaaaa",
            "name": "Vitalik",
            "child": {
              "type": "Person",
              "name": "Ethereum"
            }
          },
          "credentialSchema": {
            "id": "https://example.com/schemas/v1",
            "type": "Eip712SchemaValidator2021"
          }
        }))
        .unwrap();
        let typed_data = TypedData::from_document_and_options_json(&vc, &proof)
            .await
            .unwrap();
        // https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#example-5
        let expected_typed_data = json!({
          "types": {
            "EIP712Domain": [
              { "name": "name", "type": "string" },
              { "name": "version", "type": "string" },
              { "name": "chainId", "type": "uint256" },
              { "name": "salt", "type": "bytes32" }
            ],
            "VerifiableCredential": [
              { "name": "@context", "type": "string[]" },
              { "name": "type", "type": "string[]" },
              { "name": "id", "type": "string" },
              { "name": "issuer", "type": "string" },
              { "name": "issuanceDate", "type": "string" },
              { "name": "credentialSubject", "type": "CredentialSubject" },
              { "name": "credentialSchema", "type": "CredentialSchema" },
              { "name": "proof", "type": "Proof" }
            ],
            "CredentialSchema": [
              { "name": "id", "type": "string" },
              { "name": "type", "type": "string" }
            ],
            "CredentialSubject": [
              { "name": "type", "type": "string" },
              { "name": "id", "type": "string" },
              { "name": "name", "type": "string" },
              { "name": "child", "type": "Person" }
            ],
            "Person": [
              { "name": "type", "type": "string" },
              { "name": "name", "type": "string" }
            ],
            "Proof": [
              { "name": "verificationMethod", "type": "string" },
              { "name": "created", "type": "string" },
              { "name": "proofPurpose", "type": "string" },
              { "name": "type", "type": "string" }
            ]
          },
          "domain": {
            "name": "https://example.com",
            "version": "2",
            "chainId": 4,
            "salt": "0x000000000000000000000000000000000000000000000000aaaabbbbccccdddd"
          },
          "primaryType": "VerifiableCredential",
          "message": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://schema.org"
            ],
            "type": [
              "VerifiableCredential"
            ],
            "id": "https://example.org/person/1234",
            "issuer": "did:example:aaaabbbb",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialSubject": {
              "type": "Person",
              "id": "did:example:bbbbaaaa",
              "name": "Vitalik",
              "child": {
                "type": "Person",
                "name": "Ethereum"
              }
            },
            "credentialSchema": {
              "id": "https://example.com/schemas/v1",
              "type": "Eip712SchemaValidator2021"
            },
            "proof": {
              "verificationMethod": "did:example:aaaabbbb#issuerKey-1",
              "created": "2021-07-09T19:47:41Z",
              "proofPurpose": "assertionMethod",
              "type": "EthereumEip712Signature2021"
            }
          }
        });
        assert_eq!(
            serde_json::to_value(&typed_data).unwrap(),
            expected_typed_data
        );

        let jwk: ssi_jwk::JWK = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "cmbYyDC6cbm807_OmFNYP4CLEL0aB2F1UG683SxFkXM",
            "y": "zBw5HAh0cJM4YimSQvtYM1HFhzUXVUgrDhxJ70aajt0",
            "d": "u7QuEl6W0XNppEY0iMVjATT99tC9acwV3Z2keEqvKGo"
        }))
        .unwrap();
        eprintln!("jwk {}", serde_json::to_string(&jwk).unwrap());

        let td_jcs = serde_jcs::to_string(&typed_data).unwrap();
        // Wrap string with line breaks
        // https://stackoverflow.com/a/57032118
        let jcs_lines = td_jcs
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i != 0 && i % 90 == 0 {
                    Some('\n')
                } else {
                    None
                }
                .into_iter()
                .chain(std::iter::once(c))
            })
            .collect::<String>();
        eprintln!("JCS: [\n{}\n]", jcs_lines);

        // Sign proof
        let bytes = typed_data.bytes().unwrap();
        let ec_params = match &jwk.params {
            ssi_jwk::Params::EC(ec) => ec,
            _ => unreachable!(),
        };
        let secret_key = k256::SecretKey::try_from(ec_params).unwrap();
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let (sig, rec_id) = signing_key
            .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(bytes))
            .unwrap();
        let sig_bytes = &mut sig.to_vec();
        // Recovery ID starts at 27 instead of 0.
        sig_bytes.push(rec_id.to_byte() + 27);
        let sig_hex = ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes);
        let mut proof = proof.clone();
        proof.proof_value = Some(sig_hex.clone());
        eprintln!("proof {}", serde_json::to_string(&proof).unwrap());

        // Verify the VC/proof
        let mut vc = vc.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        vc.add_proof(proof.clone());
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        assert_eq!(sig_hex, "0xd9a03af99298b50303343ae7b89e14eb7622d64023ddb2df6c220bd5b017fa2b48ab09a6754042eeeb3785ab64f3eab1dd4fd89dbbbbd0181f135b1b938b99841c");
    }
}
