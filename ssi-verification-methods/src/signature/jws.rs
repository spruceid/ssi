use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_crypto::VerificationError;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_security::JWS;
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::XSD_STRING;

use super::AnyRef;

/// `https://w3id.org/security#jwk` signature value, encoded as a JWK.
pub struct Jws(pub CompactJWSString);

impl ssi_crypto::Referencable for Jws {
    type Reference<'a> = &'a CompactJWSStr where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        &*self.0
    }
}

impl<'a> TryFrom<AnyRef<'a>> for &'a CompactJWSStr {
    type Error = VerificationError;

    fn try_from(value: AnyRef<'a>) -> Result<Self, Self::Error> {
        match value.value {
            super::any::ValueRef::Jws(v) => Ok(v),
            _ => Err(VerificationError::InvalidSignature)
        }
    }
}

impl From<CompactJWSString> for Jws {
    fn from(value: CompactJWSString) -> Self {
        Self(value)
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for Jws
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
        if let Some(iri) = vocabulary.get(JWS) {
            if let Some(prop) = interpretation.iri_interpretation(&iri) {
                if let Some(o) = graph.objects(id, &prop).next() {
                    let value = String::from_rdf(vocabulary, interpretation, graph, o)?;
                    let jws = CompactJWSString::from_string(value)
                        .map_err(|_| FromRdfError::InvalidLexicalRepresentation)?;
                    return Ok(Self(jws));
                }
            }
        }

        Err(FromRdfError::MissingRequiredPropertyValue)
    }
}

impl<V, I> crate::json_ld::FlattenIntoJsonLdNode<V, I> for Jws
where
    V: VocabularyMut,
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        _interpretation: &I,
        node: &mut json_ld::Node<V::Iri, V::BlankId, ()>,
    ) {
        node.properties_mut().insert(
            Meta(json_ld::Id::iri(vocabulary.insert(JWS)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.0.into_string(),
                        )),
                        Some(vocabulary.insert(XSD_STRING)),
                    )),
                    None,
                ),
                (),
            ),
        )
    }
}
