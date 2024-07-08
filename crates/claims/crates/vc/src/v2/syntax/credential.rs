use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use super::{Context, InternationalString, RelatedResource};
use crate::syntax::{
    non_empty_value_or_array, not_null, value_or_array, IdOr, IdentifiedObject,
    IdentifiedTypedObject, MaybeIdentifiedTypedObject, NonEmptyObject, NonEmptyVec,
    RequiredContextList, RequiredTypeSet, TypedObject,
};
use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, ValidateClaims};
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject};
use xsd_types::DateTimeStamp;

pub use crate::v1::syntax::{CredentialType, JsonCredentialTypes, VERIFIABLE_CREDENTIAL_TYPE};

/// JSON Credential, without required context nor type.
///
/// If you care about required context and/or type, use the
/// [`SpecializedJsonCredential`] type directly.
pub type JsonCredential<S = NonEmptyObject> = SpecializedJsonCredential<S>;

/// Specialized JSON Credential with custom required context and type.
///
/// If you don't care about required context and/or type, you can use the
/// [`JsonCredential`] type alias instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "S: Serialize",
    deserialize = "S: Deserialize<'de>, C: RequiredContextList, T: RequiredTypeSet"
))]
pub struct SpecializedJsonCredential<S = NonEmptyObject, C = (), T = ()> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<C>,

    /// Credential identifier.
    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes<T>,

    /// Credential subjects.
    #[serde(rename = "credentialSubject")]
    #[serde(with = "non_empty_value_or_array")]
    pub credential_subjects: NonEmptyVec<S>,

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

    /// Evidence.
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub evidence: Vec<MaybeIdentifiedTypedObject>,

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

impl<S, C: RequiredContextList, T: RequiredTypeSet> SpecializedJsonCredential<S, C, T> {
    /// Creates a new credential.
    pub fn new(
        id: Option<UriBuf>,
        issuer: IdOr<IdentifiedObject>,
        credential_subjects: NonEmptyVec<S>,
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
            evidence: Vec::new(),
            credential_schema: Vec::new(),
            refresh_services: Vec::new(),
            extra_properties: BTreeMap::new(),
        }
    }
}

impl<S, C, T> JsonLdObject for SpecializedJsonCredential<S, C, T> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<S, C, T> JsonLdNodeObject for SpecializedJsonCredential<S, C, T> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<S, C, T, E, P> ValidateClaims<E, P> for SpecializedJsonCredential<S, C, T>
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, _proof: &P) -> ClaimsValidity {
        crate::v2::Credential::validate_credential(self, env)
    }
}

impl<S, C, T> crate::MaybeIdentified for SpecializedJsonCredential<S, C, T> {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }
}

impl<S, C, T> crate::v2::Credential for SpecializedJsonCredential<S, C, T> {
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

    fn evidence(&self) -> &[Self::Evidence] {
        &self.evidence
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        &self.credential_schema
    }
}

impl<S, C, T> ssi_json_ld::Expandable for SpecializedJsonCredential<S, C, T>
where
    S: Serialize,
{
    type Error = JsonLdError;

    type Expanded<I, V> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand_with(ld, loader).await
    }
}

#[cfg(test)]
mod tests {
    use ssi_json_ld::{CompactJsonLd, ContextLoader, Expandable};

    #[async_std::test]
    async fn reject_undefined_type() {
        let input = CompactJsonLd(json_syntax::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "@vocab": null }
            ],
            "type": [
                "VerifiableCredential",
                "ExampleTestCredential"
            ],
            "issuer": "did:example:issuer",
            "credentialSubject": {
                "id": "did:example:subject"
            }
        }));

        assert!(input.expand(&ContextLoader::default()).await.is_err());
    }
}
