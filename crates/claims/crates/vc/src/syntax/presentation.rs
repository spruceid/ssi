use std::{borrow::Cow, hash::Hash};

use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, Proof, Validate};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes};

use crate::{v1, v2};

/// Any JSON presentation using VCDM v1 or v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnyJsonPresentation<C1 = v1::syntax::JsonCredential, C2 = v2::syntax::JsonCredential> {
    V1(v1::syntax::JsonPresentation<C1>),
    V2(v2::syntax::JsonPresentation<C2>),
}

impl<C1, C2> JsonLdObject for AnyJsonPresentation<C1, C2> {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
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

impl<C1, C2, E, P: Proof> Validate<E, P> for AnyJsonPresentation<C1, C2> {
    fn validate(&self, env: &E, proof: &P::Prepared) -> ClaimsValidity {
        match self {
            Self::V1(p) => Validate::<E, P>::validate(p, env, proof),
            Self::V2(p) => Validate::<E, P>::validate(p, env, proof),
        }
    }
}

impl<V, L, E, C1, C2> ssi_rdf::Expandable<E> for AnyJsonPresentation<C1, C2>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    C1: Serialize,
    C2: Serialize,
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;

    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand(environment).await
    }
}
