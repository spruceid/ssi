use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, Proof, Validate};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes};
use std::{borrow::Cow, collections::BTreeMap, hash::Hash};
use xsd_types::DateTime;

use super::super::value_or_array;
use crate::{Context, RequiredContextSet, V1};

mod evidence;
mod issuer;
mod refresh_service;
mod schema;
mod status;
mod terms_of_use;
mod r#type;

pub use evidence::*;
pub use issuer::*;
pub use r#type::*;
pub use refresh_service::*;
pub use schema::*;
pub use status::*;
pub use terms_of_use::*;

/// JSON Credential.
pub type JsonCredential = SpecializedJsonCredential;

/// Specialized JSON Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "S: Serialize",
    deserialize = "S: Deserialize<'de>, C: RequiredContextSet, T: RequiredCredentialTypeSet"
))]
pub struct SpecializedJsonCredential<S = json_syntax::Value, C = V1, T = ()> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<C>,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes<T>,

    /// Credential subjects.
    #[serde(rename = "credentialSubject")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_subjects: Vec<S>,

    /// Issuer.
    pub issuer: Issuer,

    /// Issuance date.
    ///
    /// This property is required for validation.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: Option<xsd_types::DateTime>,

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

impl<S, C: RequiredContextSet, T: RequiredCredentialTypeSet> SpecializedJsonCredential<S, C, T> {
    pub fn new(
        id: Option<UriBuf>,
        issuer: Issuer,
        issuance_date: xsd_types::DateTime,
        credential_subjects: Vec<S>,
    ) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonCredentialTypes::default(),
            issuer,
            issuance_date: Some(issuance_date),
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

impl<S, C, T> JsonLdObject for SpecializedJsonCredential<S, C, T> {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<S, C, T> JsonLdNodeObject for SpecializedJsonCredential<S, C, T> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<S, C, T, E, P: Proof> Validate<E, P> for SpecializedJsonCredential<S, C, T>
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E, _proof: &P::Prepared) -> ClaimsValidity {
        crate::Credential::validate_credential(self, env)
    }
}

impl<S, C, T> crate::Credential for SpecializedJsonCredential<S, C, T> {
    type Subject = S;
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

    fn issuance_date(&self) -> Option<DateTime> {
        self.issuance_date
    }

    fn expiration_date(&self) -> Option<DateTime> {
        self.expiration_date
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

impl<V, L, E, S, C, T> ssi_rdf::Expandable<E> for SpecializedJsonCredential<S, C, T>
where
    S: Serialize,
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand(environment).await
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
