use std::hash::Hash;

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_crypto::VerificationError;
use ssi_jwk::JWK;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_security::JWS;
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::XSD_STRING;

use super::AnyRef;

/// `https://w3id.org/security#jwk` signature value, encoded as a JWK.
pub struct JwsPublicKeyJwk {
    pub jws: CompactJWSString,

    /// Public key.
    pub public_key_jwk: Box<JWK>,
}

impl ssi_crypto::Referencable for JwsPublicKeyJwk {
    type Reference<'a> = JwsPublicKeyJwkRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        JwsPublicKeyJwkRef {
            jws: &self.jws,
            public_key_jwk: &self.public_key_jwk
        }
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for JwsPublicKeyJwk
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
        // if let Some(iri) = vocabulary.get(JWS) {
        //     if let Some(prop) = interpretation.iri_interpretation(&iri) {
        //         if let Some(o) = graph.objects(id, &prop).next() {
        //             let value = String::from_rdf(vocabulary, interpretation, graph, o)?;
        //             let jws = CompactJWSString::from_string(value)
        //                 .map_err(|_| FromRdfError::InvalidLexicalRepresentation)?;
        //             return Ok(Self(jws));
        //         }
        //     }
        // }
        todo!()

        // Err(FromRdfError::MissingRequiredPropertyValue)
    }
}

impl<V, I> crate::json_ld::FlattenIntoJsonLdNode<V, I> for JwsPublicKeyJwk
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
        // node.properties_mut().insert(
        //     Meta(json_ld::Id::iri(vocabulary.insert(JWS)), ()),
        //     Meta(
        //         json_ld::Indexed::new(
        //             json_ld::Object::Value(json_ld::Value::Literal(
        //                 json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
        //                     self.0.into_string(),
        //                 )),
        //                 Some(vocabulary.insert(XSD_STRING)),
        //             )),
        //             None,
        //         ),
        //         (),
        //     ),
        // )
        todo!()
    }
}

pub struct JwsPublicKeyJwkRef<'a> {
    pub jws: &'a CompactJWSStr,

    /// Public key.
    pub public_key_jwk: &'a JWK,
}

impl<'a> TryFrom<AnyRef<'a>> for JwsPublicKeyJwkRef<'a> {
    type Error = VerificationError;

    fn try_from(value: AnyRef<'a>) -> Result<Self, Self::Error> {
        let jws = match value.value {
            super::any::ValueRef::Jws(v) => v,
            _ => return Err(VerificationError::InvalidSignature)
        };

        let public_key_jwk = match value.public_key {
            Some(super::any::PublicKeyRef::Jwk(jwk)) => jwk,
            _ => return Err(VerificationError::MissingPublicKey)
        };

        Ok(Self {
            jws,
            public_key_jwk
        })
    }
}