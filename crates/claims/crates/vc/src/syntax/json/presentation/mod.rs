use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use crate::{Context, Credential};
use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, Proof, Validate};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes};

use super::{super::value_or_array, SpecializedJsonCredential};

mod r#type;
pub use r#type::*;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<C> JsonLdNodeObject for JsonPresentation<C> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<C, E, P: Proof> Validate<E, P> for JsonPresentation<C> {
    fn validate(&self, _: &E, _: &P::Prepared) -> ClaimsValidity {
        Ok(())
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

    fn holder(&self) -> Option<&Uri> {
        self.holder.as_deref()
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
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand(environment).await
    }
}
