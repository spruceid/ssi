//! JSON syntax for Credentials and Presentations.
use std::{collections::BTreeMap, hash::Hash};

use chrono::{DateTime, FixedOffset};
use iref::{Uri, UriBuf};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{BlankIdInterpretationMut, Interpretation, InterpretationMut, IriInterpretationMut, LiteralInterpretationMut, VocabularyMut};
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError};
use static_iref::iri_ref;

use crate::{VERIFIABLE_CREDENTIAL_TYPE, VERIFIABLE_PRESENTATION_TYPE};

/// Verifiable Credential context.
/// 
/// This type represents the value of the `@context` property.
/// 
/// It is an ordered set where the first item is a URI with the value
/// `https://www.w3.org/2018/credentials/v1`.
#[derive(
    Debug, Serialize, Deserialize
)]
#[serde(transparent)]
pub struct Context(Vec<json_ld::syntax::ContextEntry>);

impl Default for Context {
    fn default() -> Self {
        Self(vec![json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://www.w3.org/2018/credentials/v1").to_owned(),
        )])
    }
}

/// JSON Credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Credential identifier.
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes,

    /// Credential subjects.
    #[serde(rename = "credentialSubject")]
    pub credential_subjects: Vec<json_syntax::Value>,

    /// Issuer.
    pub issuer: Issuer,

    /// Issuance date.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: xsd_types::DateTime,

    /// Proofs.
    #[serde(rename = "proof")]
    pub proofs: Vec<json_syntax::Value>,

    /// Expiration date.
    #[serde(rename = "expirationDate")]
    pub expiration_date: Option<xsd_types::DateTime>,

    /// Credential status.
    #[serde(rename = "credentialStatus")]
    pub credential_status: Vec<Status>,

    /// Terms of use.
    #[serde(rename = "termsOfUse")]
    pub terms_of_use: Vec<TermsOfUse>,

    /// Evidences.
    #[serde(rename = "evidence")]
    pub evidences: Vec<Evidence>,

    #[serde(rename = "credentialSchema")]
    pub credential_schema: Vec<Schema>,

    #[serde(rename = "refreshService")]
    pub refresh_services: Vec<RefreshService>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl crate::CredentialOrPresentation for JsonCredential {
    fn is_valid(&self) -> bool {
        crate::Credential::is_valid(self)
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

impl<V, I, L, E> ssi_rdf::Expandable<E> for JsonCredential
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::LanguageTag: Clone,
    V::Value: From<String> + From<xsd_types::Value> + From<json_syntax::Value>,
    V::Type: From<rdf_types::literal::Type<V::Iri, V::LanguageTag>>,
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri>
        + BlankIdInterpretationMut<V::BlankId>
        + LiteralInterpretationMut<V::Literal>,
    I::Resource: Clone + Ord,
    L: json_ld::Loader<V::Iri>,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send
{
    type Error = JsonLdError<L::Error>;
    type Resource = I::Resource;

    async fn expand(self, environment: &mut E) -> Result<ssi_rdf::Expanded<Self, Self::Resource>, Self::Error> {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(&self).unwrap());
        let (dataset, subject) = json.expand(environment).await?.into_rdf_parts();
        Ok(ssi_rdf::Expanded::new(self, dataset, subject))
    }
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
        S: serde::Serializer
    {
        if self.0.is_empty() {
            VERIFIABLE_CREDENTIAL_TYPE.serialize(serializer)
        } else {
            let mut seq = serializer.serialize_seq(Some(1 + self.0.len()))?;
            seq.serialize_element(VERIFIABLE_CREDENTIAL_TYPE)?;
            for t in &self.0 {
                seq.serialize_element(t)?;
            }
            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for JsonCredentialTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonCredentialTypes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "credential types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error, {
                if v == VERIFIABLE_CREDENTIAL_TYPE {
                    Ok(JsonCredentialTypes::default())
                } else {
                    Err(E::custom("expected `\"CredentialType\"`"))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>, {
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
                    Err(<A::Error as serde::de::Error>::custom("missing required `\"CredentialType\"` type"))
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// JSON Presentation.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonPresentation {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Presentation identifier.
    pub id: Option<UriBuf>,

    /// Presentation type.
    #[serde(rename = "type")]
    pub types: JsonPresentationTypes,

    /// Verifiable credentials.
    #[serde(rename = "verifiableCredentials")]
    pub verifiable_credentials: Vec<JsonCredential>,

    /// Proofs.
    #[serde(rename = "proof")]
    pub proofs: Vec<json_syntax::Value>,

    /// Holders.
    #[serde(rename = "holder")]
    pub holders: Vec<UriBuf>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl crate::CredentialOrPresentation for JsonPresentation {
    fn is_valid(&self) -> bool {
        crate::Presentation::is_valid(self)
    }
}

impl crate::Presentation for JsonPresentation {
    /// Verifiable credential type.
	type Credential = JsonCredential;
	
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
        S: serde::Serializer
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
        D: serde::Deserializer<'de>
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonPresentationTypes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "presentation types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error, {
                if v == VERIFIABLE_PRESENTATION_TYPE {
                    Ok(JsonPresentationTypes::default())
                } else {
                    Err(E::custom("expected `\"VerifiablePresentation\"`"))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>, {
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
                    Err(<A::Error as serde::de::Error>::custom("missing required `\"VerifiablePresentation\"` type"))
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