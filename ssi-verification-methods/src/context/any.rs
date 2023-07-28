use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_jwk::JWK;
use ssi_security::PUBLIC_KEY_JWK;
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::json_ld::FlattenIntoJsonLdNode;

use super::NoContext;

/// Any context, compatible with all verification methods, but faillible.
#[derive(Debug, Default, Clone)]
pub struct AnyContext {
    /// Public key, required by some verification methods.
    pub public_key_jwk: Option<Box<JWK>>,
}

impl From<NoContext> for AnyContext {
    fn from(_value: NoContext) -> Self {
        Self::default()
    }
}

impl From<AnyContext> for NoContext {
    fn from(_value: AnyContext) -> Self {}
}

impl ssi_crypto::Referencable for AnyContext {
    type Reference<'a> = AnyContextRef<'a>
		where
			Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnyContextRef {
            public_key_jwk: self.public_key_jwk.as_deref(),
        }
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for AnyContext
where
    String: FromRdf<V, I>,
{
    fn from_rdf<G>(
        vocabulary: &V,
        interpretation: &I,
        graph: &G,
        id: &I::Resource,
    ) -> Result<Self, FromRdfError>
    where
        G: Graph<Subject = I::Resource, Predicate = I::Resource, Object = I::Resource>,
    {
        let mut public_key_jwk = None;

        if let Some(iri) = vocabulary.get(PUBLIC_KEY_JWK) {
            if let Some(prop) = interpretation.iri_interpretation(&iri) {
                if let Some(o) = graph.objects(id, &prop).next() {
                    let value = String::from_rdf(vocabulary, interpretation, graph, o)?;
                    let jwk = value
                        .parse()
                        .map_err(|_| FromRdfError::InvalidLexicalRepresentation)?;
                    public_key_jwk = Some(Box::new(jwk))
                }
            }
        }

        Ok(Self { public_key_jwk })
    }
}

impl<V, I> FlattenIntoJsonLdNode<V, I> for AnyContext
where
    V: VocabularyMut,
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        _interpretation: &I,
        node: &mut json_ld::Node<<V>::Iri, <V>::BlankId>,
    ) {
        let properties = node.properties_mut();

        if let Some(public_key_jwk) = self.public_key_jwk {
            properties.insert(
                Meta(json_ld::Id::iri(vocabulary.insert(PUBLIC_KEY_JWK)), ()),
                Meta(
                    json_ld::Indexed::new(
                        json_ld::Object::Value(json_ld::Value::Json(
                            json_syntax::to_value_with(&public_key_jwk, || ()).unwrap(),
                        )),
                        None,
                    ),
                    (),
                ),
            )
        }
    }
}

/// Any context, compatible with all verification methods, but faillible.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnyContextRef<'a> {
    /// Public key, required by some verification methods.
    pub public_key_jwk: Option<&'a JWK>,
}

impl<'a> From<NoContext> for AnyContextRef<'a> {
    fn from(_value: NoContext) -> Self {
        Self::default()
    }
}

impl<'a> From<AnyContextRef<'a>> for NoContext {
    fn from(_value: AnyContextRef<'a>) -> Self {}
}
