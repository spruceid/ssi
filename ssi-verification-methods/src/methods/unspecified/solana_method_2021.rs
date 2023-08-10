use std::hash::Hash;

use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;
use ssi_security::PUBLIC_KEY_JWK;
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    covariance_rule, ExpectedType, LinkedDataVerificationMethod, Referencable, SignatureError,
    TypedVerificationMethod, VerificationError, VerificationMethod, CONTROLLER_IRI, RDF_JSON,
    RDF_TYPE_IRI,
};

pub const SOLANA_METHOD_2021_TYPE: &str = "SolanaMethod2021";

pub const SOLANA_METHOD_2021_IRI: Iri<'static> = iri!("https://w3id.org/security#SolanaMethod2021");

/// Solana Method 2021.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "SolanaMethod2021")]
pub struct SolanaMethod2021 {
    /// Key identifier.
    pub id: IriBuf,

    /// Key controller.
    pub controller: IriBuf, // TODO: should be an URI.

    /// Public JSON Web Key.
    #[serde(rename = "publicKeyJwk")]
    pub public_key: Box<JWK>,
}

impl SolanaMethod2021 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<CompactJWSString, SignatureError> {
        let algorithm = secret_key
            .algorithm
            .ok_or(SignatureError::InvalidSecretKey)?;
        let header = ssi_jws::Header::new_detached(algorithm, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(algorithm, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn verify_bytes(&self, data: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
        match self.public_key.algorithm.as_ref() {
            Some(a) => Ok(ssi_jws::verify_bytes(*a, data, &self.public_key, signature).is_ok()),
            None => Err(VerificationError::InvalidKey),
        }
    }
}

impl Referencable for SolanaMethod2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for SolanaMethod2021 {
    /// Returns the identifier of the key.
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for SolanaMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(SOLANA_METHOD_2021_TYPE.to_string().into())
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        SOLANA_METHOD_2021_TYPE
    }
}

impl LinkedDataVerificationMethod for SolanaMethod2021 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(SOLANA_METHOD_2021_IRI.into())),
            None,
        ));

        quads.push(Quad(
            Id::Iri(self.id.clone()),
            CONTROLLER_IRI.into(),
            Object::Id(Id::Iri(self.controller.clone())),
            None,
        ));

        quads.push(Quad(
            Id::Iri(self.id.clone()),
            PUBLIC_KEY_JWK.into(),
            Object::Literal(Literal::new(
                serde_json::to_string(&self.public_key).unwrap(),
                literal::Type::Any(RDF_JSON.into()),
            )),
            None,
        ));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for SolanaMethod2021
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        self.as_json_ld_object_meta(vocabulary, interpretation, meta)
    }
}

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for SolanaMethod2021
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn as_json_ld_object_meta(
        &self,
        vocabulary: &mut V,
        _interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        let mut node = json_ld::Node::with_id(json_ld::syntax::Entry::new(
            meta.clone(),
            Meta(
                json_ld::Id::Valid(Id::Iri(vocabulary.insert(self.id.as_iri()))),
                meta.clone(),
            ),
        ));

        let controller_prop = Meta(
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(CONTROLLER_IRI))),
            meta.clone(),
        );
        let controller_value = json_ld::Node::with_id(json_ld::syntax::Entry::new(
            meta.clone(),
            Meta(
                json_ld::Id::Valid(Id::Iri(vocabulary.insert(self.controller.as_iri()))),
                meta.clone(),
            ),
        ));
        node.insert(
            controller_prop,
            Meta(
                json_ld::Indexed::new(json_ld::Object::Node(Box::new(controller_value)), None),
                meta.clone(),
            ),
        );

        let key_prop = Meta(
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_JWK))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Json(
            json_syntax::to_value_with(&self.public_key, || meta.clone()).unwrap(),
        );
        node.insert(
            key_prop,
            Meta(
                json_ld::Indexed::new(json_ld::Object::Value(key_value), None),
                meta.clone(),
            ),
        );

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}
