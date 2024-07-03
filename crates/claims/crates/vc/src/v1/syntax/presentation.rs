use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use crate::syntax::{not_null, value_or_array, RequiredType, TypeSerializationPolicy, Types};
use crate::v1::{Context, Credential};
use iref::{Uri, UriBuf};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, ValidateClaims};
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader};
use ssi_rdf::{Interpretation, LdEnvironment};

use super::SpecializedJsonCredential;

pub const VERIFIABLE_PRESENTATION_TYPE: &str = "VerifiablePresentation";

pub struct PresentationType;

impl RequiredType for PresentationType {
    const REQUIRED_TYPE: &'static str = VERIFIABLE_PRESENTATION_TYPE;
}

impl TypeSerializationPolicy for PresentationType {
    const PREFER_ARRAY: bool = false;
}

pub type JsonPresentationTypes<T = ()> = Types<PresentationType, T>;

/// JSON Presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: serde::Serialize",
    deserialize = "C: serde::Deserialize<'de>"
))]
pub struct JsonPresentation<C = SpecializedJsonCredential> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Presentation identifier.
    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<UriBuf>,

    /// Presentation type.
    #[serde(rename = "type")]
    pub types: JsonPresentationTypes,

    /// Holder.
    #[serde(rename = "holder")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<UriBuf>,

    /// Verifiable credentials.
    #[serde(rename = "verifiableCredential")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verifiable_credentials: Vec<C>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl Default for JsonPresentation {
    fn default() -> Self {
        Self {
            context: Context::default(),
            id: None,
            types: JsonPresentationTypes::default(),
            verifiable_credentials: Vec::new(),
            holder: None,
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<C> JsonPresentation<C> {
    pub fn new(id: Option<UriBuf>, holder: Option<UriBuf>, verifiable_credentials: Vec<C>) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonPresentationTypes::default(),
            holder,
            verifiable_credentials,
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<C> JsonLdObject for JsonPresentation<C> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<C> JsonLdNodeObject for JsonPresentation<C> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<C, E, P> ValidateClaims<E, P> for JsonPresentation<C> {
    fn validate_claims(&self, _: &E, _: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl<C: Credential> crate::v1::Presentation for JsonPresentation<C> {
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

    fn holder(&self) -> Option<&Uri> {
        self.holder.as_deref()
    }
}

impl<C> ssi_json_ld::Expandable for JsonPresentation<C>
where
    C: Serialize,
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
