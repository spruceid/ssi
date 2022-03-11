use std::collections::HashMap as Map;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use crate::did_resolve::DIDResolver;
use crate::error::Error;
use crate::jsonld::{json_to_dataset, StaticLoader};
use crate::jwk::{JWTKeys, JWK};
use crate::jws::Header;
use crate::ldp::{
    now_ms, LinkedDataDocument, LinkedDataProofs, ProofPreparation, VerificationWarnings,
};
use crate::one_or_many::OneOrMany;
use crate::rdf::DataSet;

use async_trait::async_trait;
use chrono::{prelude::*, Duration, LocalResult};
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
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct VCDateTime {
    /// The date-time
    date_time: DateTime<FixedOffset>,
    /// Whether to use "Z" or "+00:00" when formatting the date-time in UTC
    use_z: bool,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum CheckableStatus {
    RevocationList2020Status(crate::revocation::RevocationList2020Status),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CredentialStatus: Sync {
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
    ) -> VerificationResult;
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
#[serde(untagged)]
#[serde(try_from = "String")]
pub enum StringOrURI {
    String(String),
    URI(URI),
}

/// Represents NumericDate (see https://datatracker.ietf.org/doc/html/rfc7519#section-2)
/// where the range is restricted to those in which microseconds can be exactly represented,
/// which is approximately between the years 1685 and 2255, which was considered to be sufficient
/// for the purposes of this crate.  Note that leap seconds are ignored by this type, just as
/// they're ignored by NumericDate in the JWT standard.
///
/// An f64 value has 52 explicit mantissa bits, meaning that the biggest contiguous range
/// of integer values is from -2^53 to 2^53 (52 zeros after the mantissa's implicit 1).
/// Using this value to represent exact microseconds gives a maximum range of
///     +-2^53 / (1000000 * 60 * 60 * 24 * 365.25) ~= +-285,
/// which is centered around the Unix epoch start date Jan 1, 1970, 00:00:00 UTC, giving
/// the years 1685 to 2255.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, PartialOrd)]
pub struct NumericDate(f64);

impl NumericDate {
    /// This is -2^53 / 1_000_000, which is the smallest NumericDate that faithfully
    /// represents full microsecond precision.
    pub const MIN: NumericDate = NumericDate(-9_007_199_254.740_992);
    /// This is 2^53 / 1_000_000, which is the largest NumericDate that faithfully
    /// represents full microsecond precision.
    pub const MAX: NumericDate = NumericDate(9_007_199_254.740_992);

    /// Return the f64-valued number of seconds represented by this NumericDate.
    pub fn as_seconds(self) -> f64 {
        self.0
    }
    /// Try to create NumericDate from a f64 value, returning error upon out-of-range.
    pub fn try_from_seconds(seconds: f64) -> Result<Self, Error> {
        if seconds.abs() > Self::MAX.0 {
            Err(Error::NumericDateOutOfMicrosecondPrecisionRange)
        } else {
            Ok(NumericDate(seconds))
        }
    }
    /// Decompose NumericDate for use in Utc.timestamp and Utc.timestamp_opt
    fn into_whole_seconds_and_fractional_nanoseconds(self) -> (i64, u32) {
        let whole_seconds = self.0.floor() as i64;
        let fractional_nanoseconds = ((self.0 - self.0.floor()) * 1_000_000_000.0).floor() as u32;
        assert!(fractional_nanoseconds < 1_000_000_000);
        (whole_seconds, fractional_nanoseconds)
    }
}

/// Note that this will panic if the addition goes out-of-range.
impl std::ops::Add<Duration> for NumericDate {
    type Output = NumericDate;
    fn add(self, rhs: Duration) -> Self::Output {
        let self_dtu: DateTime<Utc> = self.into();
        Self::Output::try_from(self_dtu + rhs).unwrap()
    }
}

/// Note that this will panic if the addition goes out-of-range.
impl std::ops::Sub<NumericDate> for NumericDate {
    type Output = Duration;
    fn sub(self, rhs: NumericDate) -> Self::Output {
        let self_dtu: DateTime<Utc> = self.into();
        let rhs_dtu: DateTime<Utc> = rhs.into();
        Self::Output::try_from(self_dtu - rhs_dtu).unwrap()
    }
}

/// Note that this will panic if the addition goes out-of-range.
impl std::ops::Sub<Duration> for NumericDate {
    type Output = NumericDate;
    fn sub(self, rhs: Duration) -> Self::Output {
        let self_dtu: DateTime<Utc> = self.into();
        Self::Output::try_from(self_dtu - rhs).unwrap()
    }
}

impl std::convert::TryFrom<DateTime<Utc>> for NumericDate {
    type Error = Error;
    fn try_from(dtu: DateTime<Utc>) -> Result<Self, Self::Error> {
        // Have to take seconds and nanoseconds separately in order to get the full allowable
        // range of microsecond-precision values as described above.
        let whole_seconds = dtu.timestamp() as f64;
        let fractional_seconds = dtu.timestamp_nanos().rem_euclid(1_000_000_000) as f64 * 1.0e-9;
        Ok(Self::try_from_seconds(whole_seconds + fractional_seconds)?)
    }
}

impl std::convert::TryFrom<DateTime<FixedOffset>> for NumericDate {
    type Error = Error;
    fn try_from(dtfo: DateTime<FixedOffset>) -> Result<Self, Self::Error> {
        let dtu = DateTime::<Utc>::from(dtfo);
        Ok(NumericDate::try_from(dtu)?)
    }
}

impl std::convert::Into<DateTime<Utc>> for NumericDate {
    fn into(self) -> DateTime<Utc> {
        let (whole_seconds, fractional_nanoseconds) =
            self.into_whole_seconds_and_fractional_nanoseconds();
        Utc.timestamp(whole_seconds, fractional_nanoseconds)
    }
}

impl std::convert::Into<LocalResult<DateTime<Utc>>> for NumericDate {
    fn into(self) -> LocalResult<DateTime<Utc>> {
        let (whole_seconds, fractional_nanoseconds) =
            self.into_whole_seconds_and_fractional_nanoseconds();
        Utc.timestamp_opt(whole_seconds, fractional_nanoseconds)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[non_exhaustive]
pub struct JWTClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exp")]
    pub expiration_time: Option<NumericDate>,
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

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
/// Options for specifying how the LinkedDataProof is created.
/// Reference: vc-http-api
pub struct LinkedDataProofOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    /// The type of the proof. Default is an appropriate proof type corresponding to the verification method.
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The URI of the verificationMethod used for the proof. If omitted a default
    /// assertionMethod will be used.
    pub verification_method: Option<URI>,
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
    /// Metadata for EthereumEip712Signature2021 (not standard in vc-http-api)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "keccak-hash")]
    pub eip712_domain: Option<crate::eip712::ProofInfo>,
    #[cfg(not(feature = "keccak-hash"))]
    pub eip712_domain: Option<()>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Check {
    Proof,
    #[serde(rename = "JWS")]
    JWS,
    CredentialStatus,
}

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
            eip712_domain: None,
            type_: None,
        }
    }
}

impl VerificationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn error(err: &str) -> Self {
        Self {
            checks: vec![],
            warnings: vec![],
            errors: vec![err.to_string()],
        }
    }

    pub fn append(&mut self, other: &mut Self) {
        self.checks.append(&mut other.checks);
        self.warnings.append(&mut other.warnings);
        self.errors.append(&mut other.errors);
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.errors.push(error);
        self
    }
}

impl From<Result<VerificationWarnings, Error>> for VerificationResult {
    fn from(res: Result<VerificationWarnings, Error>) -> Self {
        match res {
            Ok(warnings) => Self {
                checks: vec![],
                warnings,
                errors: vec![],
            },
            Err(error) => Self {
                checks: vec![],
                warnings: vec![],
                errors: vec![error.to_string()],
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

impl URI {
    fn as_str(&self) -> &str {
        match self {
            URI::String(string) => string.as_str(),
        }
    }
}

impl FromStr for URI {
    type Err = Error;
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        URI::try_from(String::from(uri))
    }
}

impl From<URI> for String {
    fn from(uri: URI) -> String {
        let URI::String(string) = uri;
        string
    }
}

impl std::fmt::Display for URI {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::String(ref string) => write!(f, "{}", string),
        }
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

impl From<URI> for StringOrURI {
    fn from(uri: URI) -> Self {
        StringOrURI::URI(uri)
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

pub fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

// deprecated in favor of Credential::generate_jwt and Presentation::generate_jwt
fn jwt_encode(claims: &JWTClaims, keys: &JWTKeys) -> Result<String, Error> {
    let jwk: &JWK = if let Some(rs256_key) = &keys.rs256_private_key {
        rs256_key
    } else if let Some(es256k_key) = &keys.es256k_private_key {
        es256k_key
    } else {
        return Err(Error::MissingKey);
    };
    let algorithm = jwk.get_algorithm().ok_or(Error::MissingAlgorithm)?;
    crate::jwt::encode_sign(algorithm, claims, jwk)
}

// Ensure a verification relationship exists between a given issuer and verification method for a
// given proof purpose, and that the given JWK is matches the given verification method.
pub(crate) async fn ensure_verification_relationship(
    issuer: &str,
    proof_purpose: ProofPurpose,
    vm: &str,
    jwk: &JWK,
    resolver: &dyn DIDResolver,
) -> Result<(), Error> {
    let vmms =
        crate::did_resolve::get_verification_methods(issuer, proof_purpose.clone(), resolver)
            .await?;
    let vmm = vmms.get(vm).ok_or_else(|| {
        Error::MissingVerificationRelationship(issuer.to_string(), proof_purpose, vm.to_string())
    })?;
    vmm.match_jwk(jwk)?;
    Ok(())
}

pub(crate) async fn pick_default_vm(
    issuer: &str,
    proof_purpose: ProofPurpose,
    jwk: &JWK,
    resolver: &dyn DIDResolver,
) -> Result<String, Error> {
    let vm_ids =
        crate::did_resolve::get_verification_methods(issuer, proof_purpose.clone(), resolver)
            .await?;
    let mut err = Error::MissingKey;
    for (vm_id, vmm) in vm_ids {
        // Try to find a VM that matches this JWK and controller.
        match vmm.match_jwk(jwk) {
            Ok(()) => {
                // Found appropriate VM.
                return Ok(vm_id);
            }
            Err(e) => err = e,
        }
    }
    // No matching VM found. Return any error encountered.
    Err(err)
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
            return Err(Error::AlgorithmNotImplemented);
        } else {
            return Err(Error::MissingKey);
        };
        Credential::from_jwt(jwt, jwk)
    }

    pub fn from_jwt(jwt: &str, key: &JWK) -> Result<Self, Error> {
        let token_data: JWTClaims = crate::jwt::decode_verify(jwt, key)?;
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
        if let Some(nbf) = claims.not_before {
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
            let uri = URI::try_from(id)?;
            vc.id = Some(uri);
        }
        Ok(vc)
    }

    pub fn to_jwt_claims(&self) -> Result<JWTClaims, Error> {
        let subject_opt = self.credential_subject.to_single().clone();
        let subject = match subject_opt {
            Some(subject) => match subject.id.as_ref() {
                Some(id) => Some(StringOrURI::String(id.to_string())),
                None => None,
            },
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
        crate::jwt::encode_unsigned(&claims)
    }

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
            crate::ldp::ensure_or_pick_verification_relationship(&mut options, self, jwk, resolver)
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
            jwk.get_algorithm().ok_or(Error::MissingAlgorithm)?
        } else {
            crate::jwk::Algorithm::None
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
            let sig_b64 = crate::jws::sign_bytes_b64(algorithm, signing_input.as_bytes(), jwk)?;
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
    ) -> VerificationResult {
        let (_vc, result) = Self::decode_verify_jwt(jwt, options_opt, resolver).await;
        result
    }

    pub async fn decode_verify_jwt(
        jwt: &str,
        options_opt: Option<LinkedDataProofOptions>,
        resolver: &dyn DIDResolver,
    ) -> (Option<Self>, VerificationResult) {
        let checks = options_opt
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        let (header_b64, payload_enc, signature_b64) = match crate::jws::split_jws(jwt) {
            Ok(parts) => parts,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to split JWS: {}", err)),
                );
            }
        };
        let crate::jws::DecodedJWS {
            header,
            signing_input,
            payload,
            signature,
        } = match crate::jws::decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64) {
            Ok(decoded_jws) => decoded_jws,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS: {}", err)),
                );
            }
        };
        let claims: JWTClaims = match serde_json::from_slice(&payload) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS claims: {}", err)),
                );
            }
        };
        let vc = match Self::from_jwt_claims(claims.clone()) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!(
                        "Unable to convert JWT claims to VC: {}",
                        err
                    )),
                );
            }
        };
        if let Err(err) = vc.validate_unsigned() {
            return (
                None,
                VerificationResult::error(&format!("Invalid VC: {}", err)),
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
                    VerificationResult::error(&format!("Unable to filter proofs: {}", err)),
                );
            }
        };
        let verification_method = match header.key_id {
            Some(kid) => kid,
            None => {
                return (None, VerificationResult::error("JWT header missing key id"));
            }
        };
        let key = match crate::ldp::resolve_key(&verification_method, resolver).await {
            Ok(key) => key,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to resolve key for JWS: {}", err)),
                );
            }
        };
        let mut results = VerificationResult::new();
        if matched_jwt {
            match crate::jws::verify_bytes_warnable(
                header.algorithm,
                &signing_input,
                &key,
                &signature,
            ) {
                Ok(mut warnings) => {
                    results.checks.push(Check::JWS);
                    results.warnings.append(&mut warnings);
                }
                Err(err) => results
                    .errors
                    .push(format!("Unable to filter proofs: {}", err)),
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
            let mut result = proof.verify(&vc, resolver).await;
            results.append(&mut result);
            if results.errors.is_empty() {
                results.checks.push(Check::Proof);
                break;
            };
        }
        if checks.contains(&Check::CredentialStatus) {
            results.append(&mut vc.check_status(resolver).await);
        }
        (Some(vc), results)
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
        jwt_params: Option<(&Header, &JWTClaims)>,
        resolver: &dyn DIDResolver,
    ) -> Result<(Vec<&Proof>, bool), String> {
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
                &allowed_vms,
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
    ) -> VerificationResult {
        let checks = options
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        let (proofs, _) = match self.filter_proofs(options, None, resolver).await {
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
            results.append(&mut result);
            if result.errors.is_empty() {
                results.checks.push(Check::Proof);
                break;
            };
        }
        if checks.contains(&Check::CredentialStatus) {
            results.append(&mut self.check_status(resolver).await);
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
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, resolver, jwk, None).await
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
    ) -> Result<ProofPreparation, Error> {
        LinkedDataProofs::prepare(self, options, resolver, public_key, None).await
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
    pub async fn check_status(&self, resolver: &dyn DIDResolver) -> VerificationResult {
        let status = match self.credential_status {
            Some(ref status) => status,
            None => return VerificationResult::error("Missing credentialStatus"),
        };
        let status_value = match serde_json::to_value(status.clone()) {
            Ok(status) => status,
            Err(e) => {
                return VerificationResult::error(&format!(
                    "Unable to convert credentialStatus: {}",
                    e
                ))
            }
        };
        let checkable_status: CheckableStatus = match serde_json::from_value(status_value) {
            Ok(checkable_status) => checkable_status,
            Err(e) => {
                return VerificationResult::error(&format!(
                    "Unable to parse credentialStatus: {}",
                    e
                ))
            }
        };
        let mut result = checkable_status.check(self, resolver).await;
        if !result.errors.is_empty() {
            return result;
        }
        result.checks.push(Check::CredentialStatus);
        result
    }
}

impl CheckableStatus {
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
    ) -> VerificationResult {
        match self {
            Self::RevocationList2020Status(status) => status.check(credential, resolver).await,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(&self)?)
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
        if let Some(iss) = claims.issuer {
            if let StringOrURI::URI(issuer_uri) = iss {
                vp.holder = Some(issuer_uri);
            } else {
                return Err(Error::InvalidIssuer);
            }
        }
        if let Some(id) = claims.jwt_id {
            let uri = URI::try_from(id)?;
            vp.id = Some(uri);
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
            crate::ldp::ensure_or_pick_verification_relationship(&mut options, self, jwk, resolver)
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
            jwk.get_algorithm().ok_or(Error::MissingAlgorithm)?
        } else {
            crate::jwk::Algorithm::None
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
            let sig_b64 = crate::jws::sign_bytes_b64(algorithm, signing_input.as_bytes(), jwk)?;
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
    ) -> (Option<Self>, VerificationResult) {
        let checks = options_opt
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        if checks.contains(&Check::CredentialStatus) {
            // TODO: apply check to embedded VCs
            return (
                None,
                VerificationResult::error(
                    "credentialStatus check not valid for VerifiablePresentation",
                ),
            );
        }
        // let mut options = options_opt.unwrap_or_default();
        let (header_b64, payload_enc, signature_b64) = match crate::jws::split_jws(jwt) {
            Ok(parts) => parts,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to split JWS: {}", err)),
                );
            }
        };
        let crate::jws::DecodedJWS {
            header,
            signing_input,
            payload,
            signature,
        } = match crate::jws::decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64) {
            Ok(decoded_jws) => decoded_jws,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS: {}", err)),
                );
            }
        };
        let claims: JWTClaims = match serde_json::from_slice(&payload) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to decode JWS claims: {}", err)),
                );
            }
        };
        let vp = match Self::from_jwt_claims(claims.clone()) {
            Ok(claims) => claims,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!(
                        "Unable to convert JWT claims to VP: {}",
                        err
                    )),
                );
            }
        };
        if let Err(err) = vp.validate_unsigned() {
            return (
                None,
                VerificationResult::error(&format!("Invalid VP: {}", err)),
            );
        }
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
                    VerificationResult::error(&format!("Unable to filter proofs: {}", err)),
                );
            }
        };
        let verification_method = match header.key_id {
            Some(kid) => kid,
            None => {
                return (None, VerificationResult::error("JWT header missing key id"));
            }
        };
        let key = match crate::ldp::resolve_key(&verification_method, resolver).await {
            Ok(key) => key,
            Err(err) => {
                return (
                    None,
                    VerificationResult::error(&format!("Unable to resolve key for JWS: {}", err)),
                );
            }
        };
        let mut results = VerificationResult::new();
        if matched_jwt {
            match crate::jws::verify_bytes_warnable(
                header.algorithm,
                &signing_input,
                &key,
                &signature,
            ) {
                Ok(mut warnings) => {
                    results.checks.push(Check::JWS);
                    results.warnings.append(&mut warnings);
                }
                Err(err) => results
                    .errors
                    .push(format!("Unable to filter proofs: {}", err)),
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
            let mut result = proof.verify(&vp, resolver).await;
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
    ) -> VerificationResult {
        let (_vp, result) = Self::decode_verify_jwt(jwt, options_opt, resolver).await;
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
    ) -> Result<Proof, Error> {
        LinkedDataProofs::sign(self, options, resolver, jwk, None).await
    }

    /// Prepare to generate a linked data proof. Returns the signing input for the caller to sign
    /// and then pass to [`ProofPreparation::complete`] to complete the proof.
    pub async fn prepare_proof(
        &self,
        public_key: &JWK,
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
    ) -> Result<ProofPreparation, Error> {
        LinkedDataProofs::prepare(self, options, resolver, public_key, None).await
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
        jwt_params: Option<(&Header, &JWTClaims)>,
        resolver: &dyn DIDResolver,
    ) -> Result<(Vec<&Proof>, bool), String> {
        // Allow any of holder's verification methods matching proof purpose by default
        let mut options = options.unwrap_or_else(|| LinkedDataProofOptions {
            proof_purpose: Some(ProofPurpose::Authentication),
            ..Default::default()
        });
        let allowed_vms = match options.verification_method.take() {
            Some(vm) => vec![vm.to_string()],
            None => {
                if let Some(URI::String(ref holder)) = self.holder {
                    let proof_purpose = options
                        .proof_purpose
                        .clone()
                        .unwrap_or(ProofPurpose::Authentication);
                    get_verification_methods_for_purpose(holder, resolver, proof_purpose).await?
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
                &allowed_vms,
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
    ) -> VerificationResult {
        let checks = options
            .as_ref()
            .and_then(|opts| opts.checks.clone())
            .unwrap_or_default();
        if checks.contains(&Check::CredentialStatus) {
            // TODO: apply check to embedded VCs
            return VerificationResult::error(
                "credentialStatus check not valid for VerifiablePresentation",
            );
        }
        let (proofs, _) = match self.filter_proofs(options, None, resolver).await {
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
    let doc = match crate::did_resolve::easy_resolve(did, resolver).await {
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
    let doc = crate::did_resolve::easy_resolve(did, resolver)
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
    let vmms = crate::did_resolve::get_verification_methods(did, proof_purpose.clone(), resolver)
        .await
        .map_err(String::from)?;
    Ok(vmms.into_keys().collect())
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(&self)?)
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
            ..Self::default()
        }
    }

    pub fn with_options(self, options: &LinkedDataProofOptions) -> Self {
        Self {
            proof_purpose: options.proof_purpose.clone(),
            verification_method: options
                .verification_method
                .clone()
                .map(|uri| uri.to_string()),
            domain: options.domain.clone(),
            challenge: options.challenge.clone(),
            created: Some(options.created.unwrap_or_else(now_ms)),
            ..self
        }
    }

    pub fn with_properties(self, properties: Option<Map<String, Value>>) -> Self {
        Self {
            property_set: properties,
            ..self
        }
    }

    #[allow(clippy::ptr_arg)]
    pub fn matches(&self, options: &LinkedDataProofOptions, allowed_vms: &Vec<String>) -> bool {
        if let Some(ref verification_method) = options.verification_method {
            assert_local!(
                self.verification_method.as_ref() == Some(&verification_method.to_string())
            );
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
        if let Some(ref type_) = options.type_ {
            assert_local!(&self.type_ == type_);
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

/// Evaluate if a JWT (header and claims) matches some linked data proof options.
fn jwt_matches(
    header: &Header,
    claims: &JWTClaims,
    options: &LinkedDataProofOptions,
    allowed_vms: &[String],
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
        assert_local!(allowed_vms.contains(kid));
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
        let dataset =
            json_to_dataset(&json, more_contexts.as_ref(), false, None, &mut loader).await?;
        verify_proof_consistency(self, &dataset)?;
        Ok(dataset)
    }

    fn to_value(&self) -> Result<Value, Error> {
        Ok(serde_json::to_value(&self)?)
    }
}

/// Verify alignment of proof options in JSON with RDF terms
fn verify_proof_consistency(proof: &Proof, dataset: &DataSet) -> Result<(), Error> {
    use crate::rdf;
    let mut graph_ref = dataset.default_graph.as_ref();

    let type_triple = graph_ref
        .take(
            None,
            Some(&rdf::Predicate::IRIRef(rdf::IRIRef(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
            ))),
            None,
        )
        .ok_or(Error::MissingType)?;
    let type_iri = match type_triple.object {
        rdf::Object::IRIRef(rdf::IRIRef(ref iri)) => iri,
        _ => return Err(Error::UnexpectedTriple(type_triple.clone())),
    };
    match (proof.type_.as_str(), type_iri.as_str()) {
        ("RsaSignature2018", "https://w3id.org/security#RsaSignature2018") => (),
        ("Ed25519Signature2018", "https://w3id.org/security#Ed25519Signature2018") => (),
        ("Ed25519Signature2020", "https://w3id.org/security#Ed25519Signature2020") => (),
        ("EcdsaSecp256k1Signature2019", "https://w3id.org/security#EcdsaSecp256k1Signature2019") => (),
        ("EcdsaSecp256r1Signature2019", "https://w3id.org/security#EcdsaSecp256r1Signature2019") => (),
        ("EcdsaSecp256k1RecoverySignature2020", "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoverySignature2020") => (),
        ("EcdsaSecp256k1RecoverySignature2020", "https://w3id.org/security#EcdsaSecp256k1RecoverySignature2020") => (),
        ("JsonWebSignature2020", "https://w3id.org/security#JsonWebSignature2020") => (),
        ("EthereumPersonalSignature2021", "https://demo.spruceid.com/ld/epsig/EthereumPersonalSignature2021") => (),
        ("EthereumPersonalSignature2021", "https://w3id.org/security#EthereumPersonalSignature2021") => (),
        ("Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021", "https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021") => (),
        ("P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021", "https://w3id.org/security#P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021") => (),
        ("Eip712Signature2021", "https://w3id.org/security#Eip712Signature2021") => (),
        ("TezosSignature2021", "https://w3id.org/security#TezosSignature2021") => (),
        ("TezosJcsSignature2021", "https://w3id.org/security#TezosJcsSignature2021") => (),
        ("AleoSignature2021", "https://w3id.org/security#AleoSignature2021") => (),
        ("SolanaSignature2021", "https://w3id.org/security#SolanaSignature2021") => (),
        _ => return Err(Error::UnexpectedTriple(type_triple.clone())),
    };
    let proof_id = &type_triple.subject;

    graph_ref.match_iri_property(
        proof_id,
        "https://w3id.org/security#proofPurpose",
        proof.proof_purpose.as_ref().map(|pp| pp.to_iri()),
    )?;
    graph_ref.match_iri_property(
        proof_id,
        "https://w3id.org/security#verificationMethod",
        proof.verification_method.as_deref(),
    )?;
    graph_ref.match_iri_or_string_property(
        proof_id,
        "https://w3id.org/security#challenge",
        proof.challenge.as_deref(),
    )?;
    graph_ref.match_iri_or_string_property(
        proof_id,
        "https://w3id.org/security#domain",
        proof.domain.as_deref(),
    )?;
    graph_ref.match_date_property(
        proof_id,
        "http://purl.org/dc/terms/created",
        proof.created.as_ref(),
    )?;
    graph_ref.match_json_property(
        proof_id,
        "https://w3id.org/security#publicKeyJwk",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyJwk")),
    )?;
    graph_ref.match_multibase_property(
        proof_id,
        "https://w3id.org/security#publicKeyMultibase",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("publicKeyMultibase")),
    )?;
    graph_ref.match_iri_property(
        proof_id,
        "https://w3id.org/security#capability",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("capability"))
            .and_then(|cap| cap.as_str()),
    )?;
    graph_ref.match_list_property(
        proof_id,
        "https://w3id.org/security#capabilityChain",
        proof
            .property_set
            .as_ref()
            .and_then(|cc| cc.get("capabilityChain")),
    )?;

    // Disallow additional unexpected statements
    if let Some(triple) = graph_ref.triples.into_iter().next() {
        return Err(Error::UnexpectedTriple(triple.clone()));
    }

    Ok(())
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

impl ProofPurpose {
    pub fn to_iri(&self) -> &'static str {
        match self {
            ProofPurpose::Authentication => "https://w3id.org/security#authenticationMethod",
            ProofPurpose::AssertionMethod => "https://w3id.org/security#assertionMethod",
            ProofPurpose::KeyAgreement => "https://w3id.org/security#keyAgreementMethod",
            ProofPurpose::ContractAgreement => "https://w3id.org/security#contractAgreementMethod",
            ProofPurpose::CapabilityInvocation => {
                "https://w3id.org/security#capabilityInvocationMethod"
            }
            ProofPurpose::CapabilityDelegation => {
                "https://w3id.org/security#capabilityDelegationMethod"
            }
        }
    }
}

impl FromStr for Check {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "proof" => Ok(Self::Proof),
            "JWS" => Ok(Self::JWS),
            "credentialStatus" => Ok(Self::CredentialStatus),
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
    fn from(check: Check) -> String {
        match check {
            Check::Proof => "proof".to_string(),
            Check::JWS => "JWS".to_string(),
            Check::CredentialStatus => "credentialStatus".to_string(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::did::example::DIDExample;
    use crate::urdna2015;

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

    pub const EXAMPLE_REVOCATION_2020_LIST_URL: &'static str =
        "https://example.test/revocationList.json";
    pub const EXAMPLE_REVOCATION_2020_LIST: &'static [u8] =
        include_bytes!("../tests/revocationList.json");

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

        let (vc_opt, verification_result) =
            Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
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

        let (vc1_opt, verification_result) =
            Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
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
        let (_vc_opt, verification_result) =
            Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.len() > 0);
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

        let (vc1_opt, verification_result) =
            Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
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

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(URI::String("did:example:foo#key1".to_string()));
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample)
            .await
            .unwrap();
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

        let key_str = include_str!("../tests/ed25519-2020-10-18.json");
        let key: JWK = serde_json::from_str(key_str).unwrap();

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(URI::String("did:example:foo#key3".to_string()));
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample)
            .await
            .unwrap();
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

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(URI::String("did:example:foo#key1".to_string()));
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDExample)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDExample).await;
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

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.proof_purpose = Some(ProofPurpose::AssertionMethod);
        issue_options.verification_method = Some(URI::String("did:example:foo#key1".to_string()));
        let algorithm = key.get_algorithm().unwrap();
        let public_key = key.to_public();

        let preparation = vc
            .prepare_proof(&public_key, &issue_options, &DIDExample)
            .await
            .unwrap();
        let signing_input = match preparation.signing_input {
            crate::ldp::SigningInput::Bytes(ref bytes) => &bytes.0,
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
            fn get_contexts(&self) -> Result<Option<String>, Error> {
                Ok(Some(serde_json::to_string(&self.0)?))
            }

            async fn to_dataset_for_signing(
                &self,
                _parent: Option<&(dyn LinkedDataDocument + Sync)>,
            ) -> Result<DataSet, Error> {
                Err(Error::NotImplemented)
            }

            fn to_value(&self) -> Result<Value, Error> {
                Ok(self.0.clone())
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
        good_vc(include_str!("../examples/vc.jsonld")).await;

        let vc_jwt = include_str!("../examples/vc.jwt");
        let (vc_opt, result) = Credential::decode_verify_jwt(vc_jwt, None, &DIDExample).await;
        println!("{:#?}", result);
        let vc = vc_opt.unwrap();
        println!("{:#?}", vc);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    async fn good_vc(vc_str: &str) {
        let vc = Credential::from_json(vc_str).unwrap();
        let result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    async fn bad_vc(vc_str: &str) {
        let vc = Credential::from_json(vc_str).unwrap();
        let result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", result);
        assert!(result.errors.len() > 0);
    }

    #[async_std::test]
    async fn credential_verify_proof_consistency() {
        // These test vectors were generated using examples/issue.rs with the verify part disabled,
        // and with changes made to contexts/lds-jws2020-v1.jsonld, and then copying the context
        // object into the VC.
        good_vc(include_str!("../examples/vc-jws2020-inline-context.jsonld")).await;
        bad_vc(include_str!("../examples/vc-jws2020-bad-type.jsonld")).await;
        bad_vc(include_str!("../examples/vc-jws2020-bad-purpose.jsonld")).await;
        bad_vc(include_str!("../examples/vc-jws2020-bad-method.jsonld")).await;
        bad_vc(include_str!("../examples/vc-jws2020-bad-type-json.jsonld")).await;
        bad_vc(include_str!(
            "../examples/vc-jws2020-bad-purpose-json.jsonld"
        ))
        .await;
        bad_vc(include_str!(
            "../examples/vc-jws2020-bad-method-json.jsonld"
        ))
        .await;
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
        // LDP VC in LDP VP
        let vp_str = include_str!("../examples/vp.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();
        let mut verify_options = LinkedDataProofOptions::default();
        verify_options.proof_purpose = Some(ProofPurpose::Authentication);
        let result = vp.verify(Some(verify_options.clone()), &DIDExample).await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vc = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::Credential(vc)) => vc,
            _ => unreachable!(),
        };
        let result = vc.verify(None, &DIDExample).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());

        // LDP VC in JWT VP
        let vp_jwt = include_str!("../examples/vp.jwt");
        let (vp_opt, result) =
            Presentation::decode_verify_jwt(vp_jwt, Some(verify_options.clone()), &DIDExample)
                .await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vp = vp_opt.unwrap();
        let vc = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::Credential(vc)) => vc,
            _ => unreachable!(),
        };
        let result = vc.verify(None, &DIDExample).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());

        // JWT VC in LDP VP
        let vp_str = include_str!("../examples/vp-jwtvc.jsonld");
        let vp = Presentation::from_json(vp_str).unwrap();
        let result = vp.verify(Some(verify_options.clone()), &DIDExample).await;
        println!("{:#?}", result);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vc_jwt = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::JWT(jwt)) => jwt,
            _ => unreachable!(),
        };
        let result = Credential::verify_jwt(&vc_jwt, None, &DIDExample).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());

        // JWT VC in JWT VP
        let vp_jwt = include_str!("../examples/vp-jwtvc.jwt");
        let (vp_opt, result) =
            Presentation::decode_verify_jwt(vp_jwt, Some(verify_options.clone()), &DIDExample)
                .await;
        println!("{:#?}", result);
        let vp = vp_opt.unwrap();

        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        let vc_jwt = match vp.verifiable_credential.into_iter().flatten().next() {
            Some(CredentialOrJWT::JWT(jwt)) => jwt,
            _ => unreachable!(),
        };
        let result = Credential::verify_jwt(&vc_jwt, None, &DIDExample).await;
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
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
            "credentialSubject": {},
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
            "credentialSubject": {},
            "credentialStatus": {
                "id": "_:1",
                "type": "RevocationList2020Status",
                "revocationListCredential": EXAMPLE_REVOCATION_2020_LIST_URL,
                "revocationListIndex": "1"
            }
        }))
        .unwrap();
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(URI::String("did:example:foo#key1".to_string()));
        let verify_options = LinkedDataProofOptions {
            checks: Some(vec![Check::Proof, Check::CredentialStatus]),
            ..Default::default()
        };

        // Issue unrevoked VC
        let proof = unrevoked_vc
            .generate_proof(&key, &issue_options, &DIDExample)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        unrevoked_vc.add_proof(proof);
        unrevoked_vc.validate().unwrap();

        // Issue revoked VC
        let proof = revoked_vc
            .generate_proof(&key, &issue_options, &DIDExample)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        revoked_vc.add_proof(proof);
        revoked_vc.validate().unwrap();

        // Verify unrevoked VC
        let verification_result = unrevoked_vc
            .verify(Some(verify_options.clone()), &DIDExample)
            .await;
        println!("{:#?}", verification_result);
        assert_eq!(verification_result.errors.len(), 0);

        // Verify revoked VC
        let verification_result = revoked_vc.verify(Some(verify_options), &DIDExample).await;
        println!("{:#?}", verification_result);
        assert_ne!(verification_result.errors.len(), 0);
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
        let vc_proof = vc
            .generate_proof(&key, &vc_issue_options, &DIDExample)
            .await
            .unwrap();
        vc.add_proof(vc_proof);
        println!("VC: {}", serde_json::to_string_pretty(&vc).unwrap());
        vc.validate().unwrap();
        let vc_verification_result = vc.verify(None, &DIDExample).await;
        println!("{:#?}", vc_verification_result);
        assert!(vc_verification_result.errors.is_empty());

        // Issue JWT credential
        vc_issue_options.created = None;
        let vc_jwt = vc
            .generate_jwt(Some(&key), &vc_issue_options, &DIDExample)
            .await
            .unwrap();
        let vc_verification_result = Credential::verify_jwt(&vc_jwt, None, &DIDExample).await;
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
            holder: Some(URI::String("did:example:foo".to_string())),
            property_set: None,
        };
        let vp_without_proof = vp.clone();
        let mut vp_issue_options = LinkedDataProofOptions::default();
        let vp_issuer_key = "did:example:foo#key1".to_string();
        vp_issue_options.verification_method = Some(URI::String(vp_issuer_key));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        vp_issue_options.checks = None;
        let vp_proof = vp
            .generate_proof(&key, &vp_issue_options, &DIDExample)
            .await
            .unwrap();
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
        let vp_verification_result = vp1
            .verify(Some(vp_issue_options.clone()), &DIDExample)
            .await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDExample).await.errors.len() > 0);

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
            created: None,
            checks: None,
            proof_purpose: None,
            ..Default::default()
        };
        let verification_result =
            Presentation::verify_jwt(&vp_jwt, Some(vp_jwt_verify_options.clone()), &DIDExample)
                .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
        // Edit JWT to make it fail
        let vp_jwt_bad = vp_jwt + "x";
        let verification_result = Presentation::verify_jwt(
            &vp_jwt_bad,
            Some(vp_jwt_verify_options.clone()),
            &DIDExample,
        )
        .await;
        assert!(verification_result.errors.len() > 0);

        // Test VP with JWT VC
        let vp_jwtvc = Presentation {
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::JWT(vc_jwt))),
            holder: Some(URI::String("did:example:foo".to_string())),
            ..Default::default()
        };

        // LDP VP
        let proof = vp_jwtvc
            .generate_proof(&key, &vp_issue_options.clone(), &DIDExample)
            .await
            .unwrap();
        let mut vp_jwtvc_ldp = vp_jwtvc.clone();
        vp_jwtvc_ldp.add_proof(proof);
        let vp_verify_options = vp_issue_options.clone();
        let verification_result = vp_jwtvc_ldp
            .verify(Some(vp_verify_options.clone()), &DIDExample)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // JWT VP
        let vp_vc_jwt = vp_jwtvc
            .generate_jwt(Some(&key), &vp_jwt_issue_options.clone(), &DIDExample)
            .await
            .unwrap();
        let verification_result =
            Presentation::verify_jwt(&vp_vc_jwt, Some(vp_jwt_verify_options.clone()), &DIDExample)
                .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }
}
