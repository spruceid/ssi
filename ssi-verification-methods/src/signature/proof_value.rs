use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_security::{MULTIBASE, PROOF_VALUE};
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

/// `https://w3id.org/security#proofValue` signature value, multibase-encoded.
pub struct ProofValue(pub String);

impl ssi_crypto::Referencable for ProofValue {
    type Reference<'a> = &'a str where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        &self.0
    }
}

impl From<String> for ProofValue {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for ProofValue
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
        if let Some(iri) = vocabulary.get(PROOF_VALUE) {
            if let Some(prop) = interpretation.iri_interpretation(&iri) {
                if let Some(o) = graph.objects(id, &prop).next() {
                    let value = String::from_rdf(vocabulary, interpretation, graph, o)?;
                    return Ok(Self(value));
                }
            }
        }

        Err(FromRdfError::MissingRequiredPropertyValue)
    }
}

impl<V, I> crate::json_ld::FlattenIntoJsonLdNode<V, I> for ProofValue
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
            Meta(json_ld::Id::iri(vocabulary.insert(PROOF_VALUE)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.0.to_string(),
                        )),
                        Some(vocabulary.insert(MULTIBASE)),
                    )),
                    None,
                ),
                (),
            ),
        )
    }
}
