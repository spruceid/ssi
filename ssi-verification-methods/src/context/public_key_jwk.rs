use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_crypto::Referencable;
use ssi_jwk::JWK;
use ssi_security::PUBLIC_KEY_JWK;
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::json_ld::FlattenIntoJsonLdNode;

use super::{AnyContext, AnyContextRef, ContextError};

/// Verification method context providing a JWK public key.
///
/// The key is provided by the cryptographic suite to the verification method.
#[derive(Debug, Clone)]
pub struct PublicKeyJwkContext {
    /// Public key.
    pub public_key_jwk: Box<JWK>,
}

impl PublicKeyJwkContext {
    pub fn new(public_key_jwk: JWK) -> Self {
        Self {
            public_key_jwk: Box::new(public_key_jwk),
        }
    }
}

impl From<JWK> for PublicKeyJwkContext {
    fn from(value: JWK) -> Self {
        Self::new(value)
    }
}

impl Referencable for PublicKeyJwkContext {
    type Reference<'a> = PublicKeyJwkContextRef<'a>
		where
			Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        PublicKeyJwkContextRef {
            public_key_jwk: &self.public_key_jwk,
        }
    }
}

impl From<PublicKeyJwkContext> for AnyContext {
    fn from(value: PublicKeyJwkContext) -> Self {
        Self::PublicKeyJwk(value.public_key_jwk)
    }
}

impl TryFrom<AnyContext> for PublicKeyJwkContext {
    type Error = ContextError;

    fn try_from(value: AnyContext) -> Result<Self, Self::Error> {
        match value {
            AnyContext::PublicKeyJwk(jwk) => Ok(PublicKeyJwkContext {
                public_key_jwk: jwk,
            }),
            _ => Err(ContextError::MissingPublicKey),
        }
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for PublicKeyJwkContext
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
        if let Some(iri) = vocabulary.get(PUBLIC_KEY_JWK) {
            if let Some(prop) = interpretation.iri_interpretation(&iri) {
                if let Some(o) = graph.objects(id, &prop).next() {
                    let value = String::from_rdf(vocabulary, interpretation, graph, o)?;
                    let jwk = value
                        .parse()
                        .map_err(|_| FromRdfError::InvalidLexicalRepresentation)?;
                    return Ok(Self::new(jwk));
                }
            }
        }

        Err(FromRdfError::MissingRequiredPropertyValue)
    }
}

impl<V, I> FlattenIntoJsonLdNode<V, I> for PublicKeyJwkContext
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
        node.properties_mut().insert(
            Meta(json_ld::Id::iri(vocabulary.insert(PUBLIC_KEY_JWK)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Json(
                        json_syntax::to_value_with(&self.public_key_jwk, || ()).unwrap(),
                    )),
                    None,
                ),
                (),
            ),
        )
    }
}

/// Reference to a `PublicKeyJwkContext`.
#[derive(Debug, Clone, Copy)]
pub struct PublicKeyJwkContextRef<'a> {
    /// Public key.
    pub public_key_jwk: &'a JWK,
}

impl<'a> PublicKeyJwkContextRef<'a> {
    pub fn new(public_key_jwk: &'a JWK) -> Self {
        Self { public_key_jwk }
    }
}

impl<'a> From<&'a JWK> for PublicKeyJwkContextRef<'a> {
    fn from(value: &'a JWK) -> Self {
        Self {
            public_key_jwk: value,
        }
    }
}

impl<'a> From<PublicKeyJwkContextRef<'a>> for AnyContextRef<'a> {
    fn from(value: PublicKeyJwkContextRef<'a>) -> Self {
        Self::PublicKeyJwk(value.public_key_jwk)
    }
}

impl<'a> TryFrom<AnyContextRef<'a>> for PublicKeyJwkContextRef<'a> {
    type Error = ContextError;

    fn try_from(value: AnyContextRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyContextRef::PublicKeyJwk(jwk) => Ok(Self {
                public_key_jwk: jwk,
            }),
            _ => Err(ContextError::MissingPublicKey),
        }
    }
}
