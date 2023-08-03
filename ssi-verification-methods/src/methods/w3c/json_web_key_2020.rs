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
    ExpectedType, LinkedDataVerificationMethod, VerificationMethod,
    CONTROLLER_IRI, RDF_JSON, RDF_TYPE_IRI, SignatureError, VerificationError,
};

pub const JSON_WEB_KEY_2020_TYPE: &str = "JsonWebKey2020";

pub const JSON_WEB_KEY_2020_IRI: Iri<'static> = iri!("https://w3id.org/security#JsonWebKey2020");

/// JSON Web Key 2020 verification method.
///
/// To be used with the [JSON Web Signature 2020][1] cryptographic suite.
///
/// See: <https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020>
///
/// [1]: <https://w3c-ccg.github.io/lds-jws2020>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "JsonWebKey2020")]
pub struct JsonWebKey2020 {
    /// Key identifier.
    ///
    /// Should be the JWK thumbprint calculated from the public key value
    /// according to [RFC7638][rfc7638].
    ///
    /// [rfc7638]: <https://w3c-ccg.github.io/lds-jws2020/#bib-rfc7638>
    pub id: IriBuf,

    /// Key controller.
    pub controller: IriBuf, // TODO: should be an URI.

    /// Public JSON Web Key.
    #[serde(rename = "publicKeyJwk")]
    pub public_key: Box<JWK>,
}

impl JsonWebKey2020 {
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
            Some(a) => Ok(ssi_jws::verify_bytes(
                *a,
                data,
                &self.public_key,
                signature,
            )
            .is_ok()),
            None => Err(VerificationError::InvalidKey),
        }
    }
}

impl VerificationMethod for JsonWebKey2020 {
    /// Returns the identifier of the key.
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn expected_type() -> Option<ExpectedType> {
        Some(JSON_WEB_KEY_2020_TYPE.to_string().into())
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        JSON_WEB_KEY_2020_TYPE
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, JsonWebKey2020, signature::Jws> for &'a JsonWebKey2020 {
//     /// Verifies the given signature.
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl crate::ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         data: &[u8],
//         jws: &'s CompactJWSStr,
//     ) -> Result<bool, VerificationError> {
//         controllers
//             .ensure_allows_verification_method(
//                 self.controller.as_iri(),
//                 self.id.as_iri(),
//                 proof_purpose,
//             )
//             .await?;

//         let (_, payload, signature_bytes) =
//             jws.decode().map_err(|_| VerificationError::InvalidProof)?;

//         if payload.as_ref() != data {
//             return Err(VerificationError::InvalidProof);
//         }

//         self.verify_bytes(jws.signing_bytes(), &signature_bytes)
//     }
// }

impl LinkedDataVerificationMethod for JsonWebKey2020 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(JSON_WEB_KEY_2020_IRI.into())),
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

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for JsonWebKey2020
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for JsonWebKey2020
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
