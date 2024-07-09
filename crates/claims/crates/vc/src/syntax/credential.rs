use std::{borrow::Cow, hash::Hash};

use iref::Uri;
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, ValidateClaims};
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject, Vocabulary};

use super::{RequiredContextList, RequiredTypeSet};
use crate::{v1, v2, MaybeIdentified};

/// Any JSON credential using VCDM v1 or v2.
///
/// If you care about required context and/or type, use the
/// [`AnySpecializedJsonCredential`] type directly.
pub type AnyJsonCredential<S = json_syntax::Object> = AnySpecializedJsonCredential<S>;

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
pub enum AnySpecializedJsonCredential<S = json_syntax::Object, C = (), T = ()> {
    V1(v1::syntax::SpecializedJsonCredential<S, C, T>),
    V2(v2::syntax::SpecializedJsonCredential<S, C, T>),
}

impl<S, C, T> JsonLdObject for AnySpecializedJsonCredential<S, C, T> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
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

impl<S, C, T, E, P> ValidateClaims<E, P> for AnySpecializedJsonCredential<S, C, T>
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, proof: &P) -> ClaimsValidity {
        match self {
            Self::V1(c) => c.validate_claims(env, proof),
            Self::V2(c) => c.validate_claims(env, proof),
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

impl<S, C, T> ssi_json_ld::Expandable for AnySpecializedJsonCredential<S, C, T>
where
    S: Serialize,
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

#[cfg(test)]
mod tests {
    use ssi_json_ld::{json_ld, ContextLoader, Expandable};

    use super::*;

    #[async_std::test]
    async fn reject_undefined_type_v2() {
        let input: AnyJsonCredential = serde_json::from_value(serde_json::json!({
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

    #[async_std::test]
    async fn reject_undefined_type_v1() {
        let input: AnyJsonCredential = serde_json::from_value(serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
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
