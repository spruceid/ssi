use std::{hash::Hash, borrow::Cow};

use rdf_types::{IriInterpretation, IriVocabulary, VocabularyMut};
use ssi_crypto::VerificationError;
use ssi_jwk::JWK;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_security::JWS;
use treeldr_rust_prelude::{grdf::Graph, locspan::Meta, FromRdf, FromRdfError};

use crate::XSD_STRING;

use super::AnyRef;

pub enum PublicKey {
    Jwk(Box<JWK>),
    Multibase(ssi_security::layout::Multibase)
}

impl PublicKey {
    pub fn as_reference(&self) -> PublicKeyRef {
        match self {
            Self::Jwk(jwk) => PublicKeyRef::Jwk(jwk),
            Self::Multibase(m) => PublicKeyRef::Multibase(m)
        }
    }
}

pub enum PublicKeyRef<'a> {
    Jwk(&'a JWK),
    Multibase(&'a ssi_security::layout::Multibase)
}

impl<'a> PublicKeyRef<'a> {
    pub fn as_jwk(&self) -> Result<Cow<'a, JWK>, VerificationError> {
        match self {
            Self::Jwk(jwk) => Ok(Cow::Borrowed(jwk)),
            Self::Multibase(m) => {
                let string: &str = m.as_ref();
                match string.strip_prefix('z') {
                    Some(suffix) => Ok(Cow::Owned(
                        ssi_tzkey::jwk_from_tezos_key(suffix)
                            .map_err(|_| VerificationError::InvalidKey)?,
                    )),
                    None => Err(VerificationError::InvalidKey),
                }
            }
        }
    }
}

pub struct Base58PublicKeyJwkOrMultibase {
    /// Proof value encoded in base58.
    pub proof_value: String,

    /// Optional public key.
    pub public_key: Option<PublicKey>
}

impl ssi_crypto::Referencable for Base58PublicKeyJwkOrMultibase {
    type Reference<'a> = Base58PublicKeyJwkOrMultibaseRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        Base58PublicKeyJwkOrMultibaseRef {
            proof_value: &self.proof_value,
            public_key: self.public_key.as_ref().map(|k| k.as_reference())
        }
    }
}

impl<V: IriVocabulary, I: IriInterpretation<V::Iri>> FromRdf<V, I> for Base58PublicKeyJwkOrMultibase
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

impl<V, I> crate::json_ld::FlattenIntoJsonLdNode<V, I> for Base58PublicKeyJwkOrMultibase
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

pub struct Base58PublicKeyJwkOrMultibaseRef<'a> {
    pub proof_value: &'a str,

    /// Public key.
    pub public_key: Option<PublicKeyRef<'a>>
}

impl<'a> TryFrom<AnyRef<'a>> for Base58PublicKeyJwkOrMultibaseRef<'a> {
    type Error = VerificationError;

    fn try_from(value: AnyRef<'a>) -> Result<Self, Self::Error> {
        let proof_value = match value.value {
            super::any::ValueRef::ProofValue(v) => v,
            _ => return Err(VerificationError::InvalidSignature)
        };

        let public_key = match value.public_key {
            Some(super::any::PublicKeyRef::Jwk(jwk)) => Some(PublicKeyRef::Jwk(jwk)),
            Some(super::any::PublicKeyRef::Multibase(m)) => Some(PublicKeyRef::Multibase(m)),
            None => None
        };

        Ok(Self {
            proof_value,
            public_key
        })
    }
}