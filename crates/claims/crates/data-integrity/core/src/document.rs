use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::ValidateClaims;
use ssi_core::OneOrMany;
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject, Vocabulary};

/// Any Data-Integrity-compatible document.
///
/// The only assumption made by this type is that the JSON-LD `@type` attribute
/// is aliased to `type`, which is common practice (for instance with
/// Verifiable Credentials).
///
/// Note that this type represents an *unsecured* document.
/// The type for any Data-Integrity-secured document (with the cryptosuite `S`)
/// is [`DataIntegrity<DataIntegrityDocument, S>`](crate::DataIntegrity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityDocument {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<ssi_json_ld::syntax::Context>,

    #[serde(
        rename = "type",
        alias = "@type",
        default,
        skip_serializing_if = "OneOrMany::is_empty"
    )]
    pub types: OneOrMany<String>,

    #[serde(flatten)]
    pub properties: BTreeMap<String, ssi_json_ld::syntax::Value>,
}

impl ssi_json_ld::Expandable for DataIntegrityDocument {
    type Error = JsonLdError;

    type Expanded<I: Interpretation, V: Vocabulary> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    #[allow(async_fn_in_trait)]
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

impl JsonLdObject for DataIntegrityDocument {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        self.context.as_ref().map(Cow::Borrowed)
    }
}

impl JsonLdNodeObject for DataIntegrityDocument {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        ssi_json_ld::JsonLdTypes::new(&[], Cow::Borrowed(self.types.as_slice()))
    }
}

impl<E, P> ValidateClaims<E, P> for DataIntegrityDocument {
    fn validate_claims(&self, _env: &E, _proof: &P) -> ssi_claims_core::ClaimsValidity {
        Ok(())
    }
}
