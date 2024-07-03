use std::{borrow::Cow, hash::Hash};

use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, ValidateClaims};
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject, Vocabulary};

use crate::{v1, v2};

/// Any JSON presentation using VCDM v1 or v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnyJsonPresentation<C1 = v1::syntax::JsonCredential, C2 = v2::syntax::JsonCredential> {
    V1(v1::syntax::JsonPresentation<C1>),
    V2(v2::syntax::JsonPresentation<C2>),
}

impl<C1, C2> JsonLdObject for AnyJsonPresentation<C1, C2> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        match self {
            Self::V1(p) => p.json_ld_context(),
            Self::V2(p) => p.json_ld_context(),
        }
    }
}

impl<C1, C2> JsonLdNodeObject for AnyJsonPresentation<C1, C2> {
    fn json_ld_type(&self) -> JsonLdTypes {
        match self {
            Self::V1(p) => p.json_ld_type(),
            Self::V2(p) => p.json_ld_type(),
        }
    }
}

impl<C1, C2, E, P> ValidateClaims<E, P> for AnyJsonPresentation<C1, C2> {
    fn validate_claims(&self, env: &E, proof: &P) -> ClaimsValidity {
        match self {
            Self::V1(p) => p.validate_claims(env, proof),
            Self::V2(p) => p.validate_claims(env, proof),
        }
    }
}

impl<C1, C2> ssi_json_ld::Expandable for AnyJsonPresentation<C1, C2>
where
    C1: Serialize,
    C2: Serialize,
{
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
