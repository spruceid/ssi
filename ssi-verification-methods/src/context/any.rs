use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_jwk::JWK;
use ssi_security::{PUBLIC_KEY_JWK, PUBLIC_KEY_MULTIBASE};
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::json_ld::FlattenIntoJsonLdNode;

use super::NoContext;

/// Any context, compatible with all verification methods, but faillible.
#[derive(Debug, Default, Clone)]
pub enum AnyContext {
    #[default]
    None,
    PublicKeyJwk(Box<JWK>),
    PublicKeyMultibase(ssi_security::layout::Multibase),
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
        match self {
            Self::None => AnyContextRef::None,
            Self::PublicKeyJwk(c) => AnyContextRef::PublicKeyJwk(c),
            Self::PublicKeyMultibase(c) => AnyContextRef::PublicKeyMultibase(c),
        }
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for AnyContext
where
    String: FromRdf<V, I>,
    ssi_security::layout::Multibase: FromRdf<V, I>,
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
        let mut public_key_multibase = None;

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

        if let Some(iri) = vocabulary.get(PUBLIC_KEY_MULTIBASE) {
            if let Some(prop) = interpretation.iri_interpretation(&iri) {
                if let Some(o) = graph.objects(id, &prop).next() {
                    let value = ssi_security::layout::Multibase::from_rdf(
                        vocabulary,
                        interpretation,
                        graph,
                        o,
                    )?;
                    public_key_multibase = Some(value)
                }
            }
        }

        match (public_key_jwk, public_key_multibase) {
            (None, None) => Ok(Self::None),
            (Some(public_key_jwk), None) => Ok(Self::PublicKeyJwk(public_key_jwk)),
            (None, Some(public_key_multibase)) => {
                Ok(Self::PublicKeyMultibase(public_key_multibase))
            }
            (Some(_), Some(_)) => Err(FromRdfError::UnexpectedType), // TODO use a correct error.
        }
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
        interpretation: &I,
        node: &mut json_ld::Node<<V>::Iri, <V>::BlankId>,
    ) {
        let properties = node.properties_mut();

        match self {
            Self::None => (),
            Self::PublicKeyJwk(public_key_jwk) => properties.insert(
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
            ),
            Self::PublicKeyMultibase(public_key_multibase) => {
                use treeldr_rust_prelude::AsJsonLdObjectMeta;
                node.properties_mut().insert(
                    Meta(
                        json_ld::Id::iri(vocabulary.insert(PUBLIC_KEY_MULTIBASE)),
                        (),
                    ),
                    public_key_multibase.as_json_ld_object_meta(vocabulary, interpretation, ()),
                )
            }
        }
    }
}

/// Any context, compatible with all verification methods, but faillible.
#[derive(Debug, Default, Clone, Copy)]
pub enum AnyContextRef<'a> {
    /// No context.
    #[default]
    None,

    /// Public key in JWK format, required by some verification methods.
    PublicKeyJwk(&'a JWK),

    /// Public key in multibase format, required by some verification methods.
    PublicKeyMultibase(&'a ssi_security::layout::Multibase),
}

impl<'a> From<NoContext> for AnyContextRef<'a> {
    fn from(_value: NoContext) -> Self {
        Self::default()
    }
}

impl<'a> From<AnyContextRef<'a>> for NoContext {
    fn from(_value: AnyContextRef<'a>) -> Self {}
}
