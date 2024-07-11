use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use super::{Context, InternationalString, RelatedResource};
use crate::{
    syntax::{
        non_empty_value_or_array, not_null, value_or_array, IdOr, IdentifiedObject,
        IdentifiedTypedObject, MaybeIdentifiedTypedObject, NonEmptyObject, NonEmptyVec,
        RequiredContextList, RequiredTypeSet, TypedObject,
    },
    Identified, MaybeIdentified, Typed,
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
/// If you care about required context and/or type, or want to customize other
/// aspects of the credential, use the [`SpecializedJsonCredential`] type
/// directly.
pub type JsonCredential<S = NonEmptyObject> = SpecializedJsonCredential<S>;

/// Specialized JSON Credential with custom types for each component.
///
/// If you don't care about the type of each component, you can use the
/// [`JsonCredential`] type alias instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Subject: Serialize, Issuer: Serialize, Status: Serialize, Evidence: Serialize, Schema: Serialize, RefreshService: Serialize, TermsOfUse: Serialize, ExtraProperties: Serialize",
    deserialize = "Subject: Deserialize<'de>, RequiredContext: RequiredContextList, RequiredType: RequiredTypeSet, Issuer: Deserialize<'de>, Status: Deserialize<'de>, Evidence: Deserialize<'de>, Schema: Deserialize<'de>, RefreshService: Deserialize<'de>, TermsOfUse: Deserialize<'de>, ExtraProperties: Deserialize<'de>"
))]
pub struct SpecializedJsonCredential<
    Subject = NonEmptyObject,
    RequiredContext = (),
    RequiredType = (),
    Issuer = IdOr<IdentifiedObject>,
    Status = MaybeIdentifiedTypedObject,
    Evidence = MaybeIdentifiedTypedObject,
    Schema = IdentifiedTypedObject,
    RefreshService = TypedObject,
    TermsOfUse = MaybeIdentifiedTypedObject,
    ExtraProperties = BTreeMap<String, json_syntax::Value>,
> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<RequiredContext>,

    /// Credential identifier.
    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes<RequiredType>,

    /// Credential subjects.
    #[serde(rename = "credentialSubject")]
    #[serde(with = "non_empty_value_or_array")]
    pub credential_subjects: NonEmptyVec<Subject>,

    /// Issuer.
    pub issuer: Issuer,

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
    pub credential_status: Vec<Status>,

    /// Terms of use.
    #[serde(rename = "termsOfUse")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub terms_of_use: Vec<TermsOfUse>,

    /// Evidence.
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub evidence: Vec<Evidence>,

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
    pub extra_properties: ExtraProperties,
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
    SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
where
    RequiredContext: RequiredContextList,
    RequiredType: RequiredTypeSet,
    ExtraProperties: Default,
{
    /// Creates a new credential.
    pub fn new(
        id: Option<UriBuf>,
        issuer: Issuer,
        credential_subjects: NonEmptyVec<Subject>,
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
            extra_properties: ExtraProperties::default(),
        }
    }
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    > JsonLdObject
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
{
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    > JsonLdNodeObject
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
{
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer: Identified,
        Status: MaybeIdentified + Typed,
        Evidence: MaybeIdentified + Typed,
        Schema: Identified + Typed,
        RefreshService: Typed,
        TermsOfUse: MaybeIdentified + Typed,
        ExtraProperties,
        E,
        P,
    > ValidateClaims<E, P>
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, _proof: &P) -> ClaimsValidity {
        crate::v2::Credential::validate_credential(self, env)
    }
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    > crate::MaybeIdentified
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
{
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }
}

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer: Identified,
        Status: MaybeIdentified + Typed,
        Evidence: MaybeIdentified + Typed,
        Schema: Identified + Typed,
        RefreshService: Typed,
        TermsOfUse: MaybeIdentified + Typed,
        ExtraProperties,
    > crate::v2::Credential
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
{
    type Subject = Subject;
    type Description = InternationalString;
    type Issuer = Issuer;
    type Status = Status;
    type RefreshService = RefreshService;
    type TermsOfUse = TermsOfUse;
    type Evidence = Evidence;
    type Schema = Schema;
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

impl<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    > ssi_json_ld::Expandable
    for SpecializedJsonCredential<
        Subject,
        RequiredContext,
        RequiredType,
        Issuer,
        Status,
        Evidence,
        Schema,
        RefreshService,
        TermsOfUse,
        ExtraProperties,
    >
where
    Subject: Serialize,
    Issuer: Serialize,
    Status: Serialize,
    Evidence: Serialize,
    Schema: Serialize,
    RefreshService: Serialize,
    TermsOfUse: Serialize,
    ExtraProperties: Serialize,
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
    use ssi_json_ld::{json_ld, ContextLoader, Expandable};

    use super::*;

    #[async_std::test]
    async fn reject_undefined_type() {
        let input: JsonCredential = serde_json::from_value(serde_json::json!({
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
        }))
        .unwrap();
        match input.expand(&ContextLoader::default()).await.unwrap_err() {
            JsonLdError::Expansion(json_ld::expansion::Error::InvalidTypeValue) => (),
            e => panic!("{:?}", e),
        }
    }
}
