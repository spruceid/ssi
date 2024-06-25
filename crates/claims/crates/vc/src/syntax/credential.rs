use std::{borrow::Cow, hash::Hash};

use iref::Uri;
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, Proof, Validate};
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes};

use super::{RequiredContextList, RequiredTypeSet};
use crate::{v1, v2, MaybeIdentified};

/// Any JSON credential using VCDM v1 or v2.
///
/// If you care about required context and/or type, use the
/// [`AnySpecializedJsonCredential`] type directly.
pub type AnyJsonCredential<S = json_syntax::Value> = AnySpecializedJsonCredential<S>;

/// Any JSON credential using VCDM v1 or v2 with custom required contexts and
/// types.
///
/// If you don't care about required context and/or type, you can use the
/// [`AnyJsonCredential`] type alias instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    untagged,
    bound(
        serialize = "S: Serialize",
        deserialize = "S: Deserialize<'de>, C: RequiredContextList, T: RequiredTypeSet"
    )
)]
pub enum AnySpecializedJsonCredential<S = json_syntax::Value, C = (), T = ()> {
    V1(v1::syntax::SpecializedJsonCredential<S, C, T>),
    V2(v2::syntax::SpecializedJsonCredential<S, C, T>),
}

impl<S, C, T> JsonLdObject for AnySpecializedJsonCredential<S, C, T> {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        match self {
            Self::V1(c) => c.json_ld_context(),
            Self::V2(c) => c.json_ld_context(),
        }
    }
}

impl<S, C, T> JsonLdNodeObject for AnySpecializedJsonCredential<S, C, T> {
    fn json_ld_type(&self) -> JsonLdTypes {
        match self {
            Self::V1(c) => c.json_ld_type(),
            Self::V2(c) => c.json_ld_type(),
        }
    }
}

impl<S, C, T, E, P: Proof> Validate<E, P> for AnySpecializedJsonCredential<S, C, T>
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E, proof: &P::Prepared) -> ClaimsValidity {
        match self {
            Self::V1(c) => Validate::<E, P>::validate(c, env, proof),
            Self::V2(c) => Validate::<E, P>::validate(c, env, proof),
        }
    }
}

impl<S, C, T> MaybeIdentified for AnySpecializedJsonCredential<S, C, T> {
    fn id(&self) -> Option<&Uri> {
        match self {
            Self::V1(c) => c.id(),
            Self::V2(c) => c.id(),
        }
    }
}

impl<V, L, E, S, C, T> ssi_rdf::Expandable<E> for AnySpecializedJsonCredential<S, C, T>
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
