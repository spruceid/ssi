//! JSON syntax for Credentials and Presentations.
use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use super::value_or_array;
use chrono::{DateTime, FixedOffset};
use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use ssi_claims_core::{ExtractProof, Validate, VerifiableClaims};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, WithJsonLdContext};

use crate::{Context, Credential, VERIFIABLE_CREDENTIAL_TYPE, VERIFIABLE_PRESENTATION_TYPE};

/// JSON Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes,

    /// Credential subjects.
    #[serde(rename = "credentialSubject")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_subjects: Vec<json_syntax::Value>,

    /// Issuer.
    pub issuer: Issuer,

    /// Issuance date.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: xsd_types::DateTime,

    /// Expiration date.
    #[serde(rename = "expirationDate")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<xsd_types::DateTime>,

    /// Credential status.
    #[serde(rename = "credentialStatus")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_status: Vec<Status>,

    /// Terms of use.
    #[serde(rename = "termsOfUse")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub terms_of_use: Vec<TermsOfUse>,

    /// Evidences.
    #[serde(rename = "evidence")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub evidences: Vec<Evidence>,

    #[serde(rename = "credentialSchema")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_schema: Vec<Schema>,

    #[serde(rename = "refreshService")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub refresh_services: Vec<RefreshService>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl JsonCredential {
    pub fn new(
        id: Option<UriBuf>,
        issuer: Issuer,
        issuance_date: xsd_types::DateTime,
        credential_subjects: Vec<json_syntax::Value>,
    ) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonCredentialTypes::default(),
            issuer,
            issuance_date,
            credential_subjects,
            expiration_date: None,
            credential_status: Vec::new(),
            terms_of_use: Vec::new(),
            evidences: Vec::new(),
            credential_schema: Vec::new(),
            refresh_services: Vec::new(),
            additional_properties: BTreeMap::new(),
        }
    }
}

impl WithJsonLdContext for JsonCredential {
    fn json_ld_context(&self) -> Cow<json_ld::syntax::Context> {
        Cow::Borrowed(&self.context.0)
    }
}

impl Validate for JsonCredential {
    fn is_valid(&self) -> bool {
        crate::Credential::is_valid_credential(self)
    }
}

impl crate::Credential for JsonCredential {
    type Subject = json_syntax::Value;
    type Issuer = Issuer;
    type Status = Status;
    type RefreshService = RefreshService;
    type TermsOfUse = TermsOfUse;
    type Evidence = Evidence;
    type Schema = Schema;

    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    fn additional_types(&self) -> &[String] {
        self.types.additional_types()
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        &self.credential_subjects
    }

    fn issuer(&self) -> &Self::Issuer {
        &self.issuer
    }

    fn issuance_date(&self) -> DateTime<FixedOffset> {
        self.issuance_date.into()
    }

    fn expiration_date(&self) -> Option<DateTime<FixedOffset>> {
        self.expiration_date.map(Into::into)
    }

    fn credential_status(&self) -> &[Self::Status] {
        &self.credential_status
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        &self.refresh_services
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        &self.terms_of_use
    }

    fn evidences(&self) -> &[Self::Evidence] {
        &self.evidences
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        &self.credential_schema
    }
}

impl<V, L, E> ssi_rdf::Expandable<E> for JsonCredential
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
{
    type Error = JsonLdError<L::Error>;
    // type Resource = I::Resource;

    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand(environment).await
    }
}

/// JSON Verifiable Credential.
///
/// The `P` parameter is the proof format type.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: serde::Serialize",
    deserialize = "P: serde::Deserialize<'de>"
))]
pub struct JsonVerifiableCredential<P = json_syntax::Value> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes,

    /// Credential subjects.
    #[serde(rename = "credentialSubject")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_subjects: Vec<json_syntax::Value>,

    /// Issuer.
    pub issuer: Issuer,

    /// Issuance date.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: xsd_types::DateTime,

    /// Proofs.
    #[serde(rename = "proof")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub proofs: Vec<P>,

    /// Expiration date.
    #[serde(rename = "expirationDate")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<xsd_types::DateTime>,

    /// Credential status.
    #[serde(rename = "credentialStatus")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_status: Vec<Status>,

    /// Terms of use.
    #[serde(rename = "termsOfUse")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub terms_of_use: Vec<TermsOfUse>,

    /// Evidences.
    #[serde(rename = "evidence")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub evidences: Vec<Evidence>,

    #[serde(rename = "credentialSchema")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_schema: Vec<Schema>,

    #[serde(rename = "refreshService")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub refresh_services: Vec<RefreshService>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl<P> JsonVerifiableCredential<P> {
    pub fn new(
        id: Option<UriBuf>,
        issuer: Issuer,
        issuance_date: xsd_types::DateTime,
        credential_subjects: Vec<json_syntax::Value>,
        proofs: Vec<P>,
    ) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonCredentialTypes::default(),
            issuer,
            issuance_date,
            proofs,
            credential_subjects,
            expiration_date: None,
            credential_status: Vec::new(),
            terms_of_use: Vec::new(),
            evidences: Vec::new(),
            credential_schema: Vec::new(),
            refresh_services: Vec::new(),
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<P> Validate for JsonVerifiableCredential<P> {
    fn is_valid(&self) -> bool {
        crate::Credential::is_valid_credential(self)
    }
}

impl<P> crate::Credential for JsonVerifiableCredential<P> {
    type Subject = json_syntax::Value;
    type Issuer = Issuer;
    type Status = Status;
    type RefreshService = RefreshService;
    type TermsOfUse = TermsOfUse;
    type Evidence = Evidence;
    type Schema = Schema;

    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    fn additional_types(&self) -> &[String] {
        self.types.additional_types()
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        &self.credential_subjects
    }

    fn issuer(&self) -> &Self::Issuer {
        &self.issuer
    }

    fn issuance_date(&self) -> DateTime<FixedOffset> {
        self.issuance_date.into()
    }

    fn expiration_date(&self) -> Option<DateTime<FixedOffset>> {
        self.expiration_date.map(Into::into)
    }

    fn credential_status(&self) -> &[Self::Status] {
        &self.credential_status
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        &self.refresh_services
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        &self.terms_of_use
    }

    fn evidences(&self) -> &[Self::Evidence] {
        &self.evidences
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        &self.credential_schema
    }
}

impl<P> VerifiableClaims for JsonVerifiableCredential<P> {
    type Proof = Vec<P>;

    fn proof(&self) -> &Vec<P> {
        &self.proofs
    }
}

impl<P> ExtractProof for JsonVerifiableCredential<P> {
    type Proofless = JsonCredential;

    fn extract_proof(self) -> (Self::Proofless, Vec<P>) {
        let credential = JsonCredential {
            context: self.context,
            id: self.id,
            types: self.types,
            credential_subjects: self.credential_subjects,
            issuer: self.issuer,
            issuance_date: self.issuance_date,
            expiration_date: self.expiration_date,
            credential_status: self.credential_status,
            terms_of_use: self.terms_of_use,
            evidences: self.evidences,
            credential_schema: self.credential_schema,
            refresh_services: self.refresh_services,
            additional_properties: self.additional_properties,
        };

        (credential, self.proofs)
    }
}

pub trait ProcessedProof {
    type Processed;
}

#[derive(Debug, Default, Clone)]
pub struct JsonCredentialTypes(Vec<String>);

impl JsonCredentialTypes {
    pub fn additional_types(&self) -> &[String] {
        &self.0
    }
}

impl Serialize for JsonCredentialTypes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1 + self.0.len()))?;
        seq.serialize_element(VERIFIABLE_CREDENTIAL_TYPE)?;
        for t in &self.0 {
            seq.serialize_element(t)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for JsonCredentialTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonCredentialTypes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "credential types")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut base_type = false;
                let mut types = Vec::new();

                while let Some(t) = seq.next_element()? {
                    if t == VERIFIABLE_CREDENTIAL_TYPE {
                        base_type = true
                    } else {
                        types.push(t)
                    }
                }

                if base_type {
                    Ok(JsonCredentialTypes(types))
                } else {
                    Err(<A::Error as serde::de::Error>::custom(
                        "missing required `\"CredentialType\"` type",
                    ))
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// JSON Presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: serde::Serialize",
    deserialize = "C: serde::Deserialize<'de>"
))]
pub struct JsonPresentation<C = JsonCredential> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Presentation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Presentation type.
    #[serde(rename = "type")]
    pub types: JsonPresentationTypes,

    /// Verifiable credentials.
    #[serde(rename = "verifiableCredential")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verifiable_credentials: Vec<C>,

    /// Holders.
    #[serde(rename = "holder")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub holders: Vec<UriBuf>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl<C> JsonPresentation<C> {
    pub fn new(id: Option<UriBuf>, verifiable_credentials: Vec<C>, holders: Vec<UriBuf>) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonPresentationTypes::default(),
            verifiable_credentials,
            holders,
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<C> WithJsonLdContext for JsonPresentation<C> {
    fn json_ld_context(&self) -> Cow<json_ld::syntax::Context> {
        Cow::Borrowed(self.context.as_ref())
    }
}

impl<C: Credential> Validate for JsonPresentation<C> {
    fn is_valid(&self) -> bool {
        crate::Presentation::is_valid_presentation(self)
    }
}

impl<C: Credential> crate::Presentation for JsonPresentation<C> {
    /// Verifiable credential type.
    type Credential = C;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    /// Types, without the `VerifiablePresentation` type.
    fn additional_types(&self) -> &[String] {
        self.types.additional_types()
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        &self.verifiable_credentials
    }

    fn holders(&self) -> &[UriBuf] {
        &self.holders
    }
}

impl<V, L, E, C> ssi_rdf::Expandable<E> for JsonPresentation<C>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    C: Serialize,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
{
    type Error = JsonLdError<L::Error>;

    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand(environment).await
    }
}

/// JSON Verifiable Presentation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: serde::Serialize, P: serde::Serialize",
    deserialize = "C: serde::Deserialize<'de>, P: serde::Deserialize<'de>"
))]
pub struct JsonVerifiablePresentation<C = JsonCredential, P = json_syntax::Value> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Presentation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Presentation type.
    #[serde(rename = "type")]
    pub types: JsonPresentationTypes,

    /// Verifiable credentials.
    #[serde(rename = "verifiableCredential")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verifiable_credentials: Vec<C>,

    /// Proofs.
    #[serde(rename = "proof")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub proofs: Vec<P>,

    /// Holders.
    #[serde(rename = "holder")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub holders: Vec<UriBuf>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl<C, P> JsonVerifiablePresentation<C, P> {
    pub fn new(
        id: Option<UriBuf>,
        verifiable_credentials: Vec<C>,
        holders: Vec<UriBuf>,
        proofs: Vec<P>,
    ) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonPresentationTypes::default(),
            verifiable_credentials,
            proofs,
            holders,
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<C: Credential, P> Validate for JsonVerifiablePresentation<C, P> {
    fn is_valid(&self) -> bool {
        crate::Presentation::is_valid_presentation(self)
    }
}

impl<C: Credential, P> crate::Presentation for JsonVerifiablePresentation<C, P> {
    /// Verifiable credential type.
    type Credential = C;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    /// Types, without the `VerifiablePresentation` type.
    fn additional_types(&self) -> &[String] {
        self.types.additional_types()
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        &self.verifiable_credentials
    }

    fn holders(&self) -> &[UriBuf] {
        &self.holders
    }
}

impl<C, P> VerifiableClaims for JsonVerifiablePresentation<C, P> {
    type Proof = Vec<P>;

    fn proof(&self) -> &Vec<P> {
        &self.proofs
    }
}

impl<C, P> ExtractProof for JsonVerifiablePresentation<C, P> {
    type Proofless = JsonPresentation<C>;

    fn extract_proof(self) -> (Self::Proofless, Vec<P>) {
        let presentation = JsonPresentation {
            context: self.context,
            id: self.id,
            types: self.types,
            verifiable_credentials: self.verifiable_credentials,
            holders: self.holders,
            additional_properties: self.additional_properties,
        };

        (presentation, self.proofs)
    }
}

#[derive(Debug, Default, Clone)]
pub struct JsonPresentationTypes(Vec<String>);

impl JsonPresentationTypes {
    pub fn additional_types(&self) -> &[String] {
        &self.0
    }
}

impl Serialize for JsonPresentationTypes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.is_empty() {
            VERIFIABLE_PRESENTATION_TYPE.serialize(serializer)
        } else {
            let mut seq = serializer.serialize_seq(Some(1 + self.0.len()))?;
            seq.serialize_element(VERIFIABLE_PRESENTATION_TYPE)?;
            for t in &self.0 {
                seq.serialize_element(t)?;
            }
            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for JsonPresentationTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonPresentationTypes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "presentation types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v == VERIFIABLE_PRESENTATION_TYPE {
                    Ok(JsonPresentationTypes::default())
                } else {
                    Err(E::custom("expected `\"VerifiablePresentation\"`"))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut base_type = false;
                let mut types = Vec::new();

                while let Some(t) = seq.next_element()? {
                    if t == VERIFIABLE_PRESENTATION_TYPE {
                        base_type = true
                    } else {
                        types.push(t)
                    }
                }

                if base_type {
                    Ok(JsonPresentationTypes(types))
                } else {
                    Err(<A::Error as serde::de::Error>::custom(
                        "missing required `\"VerifiablePresentation\"` type",
                    ))
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Issuer {
    Uri(UriBuf),
    Object(ObjectWithId),
}

impl From<UriBuf> for Issuer {
    fn from(value: UriBuf) -> Self {
        Self::Uri(value)
    }
}

impl crate::Issuer for Issuer {
    fn id(&self) -> &Uri {
        match self {
            Self::Uri(uri) => uri,
            Self::Object(object) => &object.id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWithId {
    pub id: UriBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::RefreshService for RefreshService {
    fn id(&self) -> &Uri {
        &self.id
    }

    fn type_(&self) -> &str {
        &self.type_
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::TermsOfUse for TermsOfUse {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    fn type_(&self) -> &str {
        &self.type_
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    #[serde(rename = "type")]
    pub type_: Vec<String>,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::Evidence for Evidence {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    fn type_(&self) -> &[String] {
        &self.type_
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::CredentialStatus for Status {
    fn id(&self) -> &Uri {
        &self.id
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}
