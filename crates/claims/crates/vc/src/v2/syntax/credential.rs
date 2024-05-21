use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use super::{Context, InternationalString, RelatedResource};
use crate::syntax::{
    value_or_array, IdOr, IdentifiedObject, IdentifiedTypedObject, MaybeIdentifiedTypedObject,
    RequiredContextList, RequiredTypeSet, TypedObject,
};
use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, Proof, Validate};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes};
use xsd_types::DateTimeStamp;

pub use crate::v1::syntax::{CredentialType, JsonCredentialTypes, VERIFIABLE_CREDENTIAL_TYPE};

/// JSON Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "S: Serialize",
    deserialize = "S: Deserialize<'de>, C: RequiredContextList, T: RequiredTypeSet"
))]
pub struct JsonCredential<S = json_syntax::Value, C = (), T = ()> {
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
    pub issuer: IdOr<IdentifiedObject>,

    /// Issuance date.
    #[serde(rename = "validFrom")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<xsd_types::DateTimeStamp>,

    /// Expiration date.
    #[serde(rename = "validUntil")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<xsd_types::DateTimeStamp>,

    /// Credential status.
    #[serde(rename = "credentialStatus")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_status: Vec<MaybeIdentifiedTypedObject>,

    /// Terms of use.
    #[serde(rename = "termsOfUse")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub terms_of_use: Vec<MaybeIdentifiedTypedObject>,

    /// Evidences.
    #[serde(rename = "evidence")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub evidences: Vec<MaybeIdentifiedTypedObject>,

    #[serde(rename = "credentialSchema")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_schema: Vec<IdentifiedTypedObject>,

    #[serde(rename = "refreshService")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub refresh_services: Vec<TypedObject>,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<S, C: RequiredContextList, T: RequiredTypeSet> JsonCredential<S, C, T> {
    pub fn new(
        id: Option<UriBuf>,
        issuer: IdOr<IdentifiedObject>,
        credential_subjects: Vec<S>,
    ) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonCredentialTypes::default(),
            issuer,
            credential_subjects,
            valid_from: None,
            valid_until: None,
            credential_status: Vec::new(),
            terms_of_use: Vec::new(),
            evidences: Vec::new(),
            credential_schema: Vec::new(),
            refresh_services: Vec::new(),
            extra_properties: BTreeMap::new(),
        }
    }
}

impl<S, C, T> JsonLdObject for JsonCredential<S, C, T> {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<S, C, T> JsonLdNodeObject for JsonCredential<S, C, T> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<S, C, T, E, P: Proof> Validate<E, P> for JsonCredential<S, C, T>
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E, _proof: &P::Prepared) -> ClaimsValidity {
        crate::v2::Credential::validate_credential(self, env)
    }
}

impl<S, C, T> crate::MaybeIdentified for JsonCredential<S, C, T> {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }
}

impl<S, C, T> crate::v2::Credential for JsonCredential<S, C, T> {
    type Subject = S;
    type Description = InternationalString;
    type Issuer = IdOr<IdentifiedObject>;
    type Status = MaybeIdentifiedTypedObject;
    type RefreshService = TypedObject;
    type TermsOfUse = MaybeIdentifiedTypedObject;
    type Evidence = MaybeIdentifiedTypedObject;
    type Schema = IdentifiedTypedObject;
    type RelatedResource = RelatedResource;

    fn additional_types(&self) -> &[String] {
        self.types.additional_types()
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        &self.credential_subjects
    }

    fn issuer(&self) -> &Self::Issuer {
        &self.issuer
    }

    fn valid_from(&self) -> Option<DateTimeStamp> {
        self.valid_from
    }

    fn valid_until(&self) -> Option<DateTimeStamp> {
        self.valid_until
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

impl<V, L, E, S, C, T> ssi_rdf::Expandable<E> for JsonCredential<S, C, T>
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
