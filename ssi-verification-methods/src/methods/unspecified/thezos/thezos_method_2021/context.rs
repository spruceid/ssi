use std::{borrow::Cow, hash::Hash};

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_crypto::{Referencable, VerificationError};
use ssi_jwk::JWK;
use ssi_security::{PUBLIC_KEY_JWK, PUBLIC_KEY_MULTIBASE};
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::{json_ld::FlattenIntoJsonLdNode, AnyContext, AnyContextRef, ContextError};

/// Verification method context providing a JWK public key.
///
/// The key is provided by the cryptographic suite to the verification method.
#[derive(Debug, Clone)]
pub enum Context {
    None,
    PublicKeyJwk(Box<JWK>),
    PublicKeyMultibase(ssi_security::layout::Multibase),
}

impl From<JWK> for Context {
    fn from(value: JWK) -> Self {
        Self::PublicKeyJwk(Box::new(value))
    }
}

impl From<ssi_security::layout::Multibase> for Context {
    fn from(value: ssi_security::layout::Multibase) -> Self {
        Self::PublicKeyMultibase(value)
    }
}

impl Referencable for Context {
    type Reference<'a> = ContextRef<'a>
		where
			Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        match self {
            Self::None => ContextRef::None,
            Self::PublicKeyJwk(c) => ContextRef::PublicKeyJwk(c),
            Self::PublicKeyMultibase(c) => ContextRef::PublicKeyMultibase(c),
        }
    }
}

impl From<Context> for AnyContext {
    fn from(value: Context) -> Self {
        match value {
            Context::None => Self::None,
            Context::PublicKeyJwk(c) => Self::PublicKeyJwk(c),
            Context::PublicKeyMultibase(c) => Self::PublicKeyMultibase(c),
        }
    }
}

impl TryFrom<AnyContext> for Context {
    type Error = ContextError;

    fn try_from(value: AnyContext) -> Result<Self, Self::Error> {
        match value {
            AnyContext::None => Err(ContextError::MissingPublicKey),
            AnyContext::PublicKeyJwk(c) => Ok(Self::PublicKeyJwk(c)),
            AnyContext::PublicKeyMultibase(c) => Ok(Self::PublicKeyMultibase(c)),
        }
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for Context
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

impl<V, I> FlattenIntoJsonLdNode<V, I> for Context
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
        match self {
            Self::None => (),
            Self::PublicKeyJwk(public_key_jwk) => node.properties_mut().insert(
                Meta(json_ld::Id::iri(vocabulary.insert(PUBLIC_KEY_JWK)), ()),
                Meta(
                    json_ld::Indexed::new(
                        json_ld::Object::Value(json_ld::Value::Json(
                            json_syntax::to_value_with(public_key_jwk, || ()).unwrap(),
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

/// Reference to a `PublicKeyJwkContext`.
#[derive(Debug, Clone, Copy)]
pub enum ContextRef<'a> {
    None,
    PublicKeyJwk(&'a JWK),
    PublicKeyMultibase(&'a ssi_security::layout::Multibase),
}

impl<'a> ContextRef<'a> {
    pub fn as_jwk(&self) -> Result<Option<Cow<'a, JWK>>, VerificationError> {
        match self {
            Self::None => Ok(None),
            Self::PublicKeyJwk(jwk) => Ok(Some(Cow::Borrowed(jwk))),
            Self::PublicKeyMultibase(m) => {
                let string: &str = m.as_ref();
                match string.strip_prefix('z') {
                    Some(suffix) => Ok(Some(Cow::Owned(
                        ssi_tzkey::jwk_from_tezos_key(suffix)
                            .map_err(|_| VerificationError::InvalidKey)?,
                    ))),
                    None => Err(VerificationError::InvalidKey),
                }
            }
        }
    }
}

impl<'a> From<&'a JWK> for ContextRef<'a> {
    fn from(value: &'a JWK) -> Self {
        Self::PublicKeyJwk(value)
    }
}

impl<'a> From<&'a ssi_security::layout::Multibase> for ContextRef<'a> {
    fn from(value: &'a ssi_security::layout::Multibase) -> Self {
        Self::PublicKeyMultibase(value)
    }
}

impl<'a> From<ContextRef<'a>> for AnyContextRef<'a> {
    fn from(value: ContextRef<'a>) -> Self {
        match value {
            ContextRef::None => AnyContextRef::None,
            ContextRef::PublicKeyJwk(jwk) => AnyContextRef::PublicKeyJwk(jwk),
            ContextRef::PublicKeyMultibase(m) => AnyContextRef::PublicKeyMultibase(m),
        }
    }
}

impl<'a> TryFrom<AnyContextRef<'a>> for ContextRef<'a> {
    type Error = ContextError;

    fn try_from(value: AnyContextRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyContextRef::None => Err(ContextError::MissingPublicKey),
            AnyContextRef::PublicKeyJwk(c) => Ok(Self::PublicKeyJwk(c)),
            AnyContextRef::PublicKeyMultibase(c) => Ok(Self::PublicKeyMultibase(c)),
        }
    }
}
