use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_crypto::VerificationError;
use ssi_security::SIGNATURE_VALUE;
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::XSD_STRING;

/// `https://w3id.org/security#signatureValue` signature value, encoded in
/// base64.
pub struct SignatureValueBuf(pub String);

impl SignatureValueBuf {
    pub fn as_signature_value(&self) -> &SignatureValue {
        unsafe { std::mem::transmute(self.0.as_str()) }
    }
}

impl From<String> for SignatureValueBuf {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for SignatureValueBuf {
    type Target = SignatureValue;

    fn deref(&self) -> &Self::Target {
        self.as_signature_value()
    }
}

/// Unsized `https://w3id.org/security#signatureValue` signature value, encoded
/// in base64.
#[repr(transparent)]
pub struct SignatureValue(str);

impl ssi_crypto::Referencable for SignatureValueBuf {
    type Reference<'a> = &'a SignatureValue where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self.as_signature_value()
    }
}

impl SignatureValue {
    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        multibase::Base::Base64
            .decode(&self.0)
            .map_err(|_| VerificationError::InvalidProof)
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for SignatureValueBuf
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
        if let Some(iri) = vocabulary.get(SIGNATURE_VALUE) {
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

impl<V, I> crate::json_ld::FlattenIntoJsonLdNode<V, I> for SignatureValueBuf
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
            Meta(json_ld::Id::iri(vocabulary.insert(SIGNATURE_VALUE)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.0,
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
