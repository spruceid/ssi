use std::hash::Hash;

use async_trait::async_trait;
use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_crypto::{SignatureError, VerificationError};
use ssi_jwk::JWK;
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    LinkedDataVerificationMethod, VerificationMethod, VerificationMethodRef, CONTROLLER_IRI,
    PUBLIC_KEY_JWK_IRI, RDF_JSON, RDF_TYPE_IRI,
};

pub const RSA_VERIFICATION_KEY_2018_TYPE: &str = "RsaVerificationKey2018";

pub const RSA_VERIFICATION_KEY_2018_IRI: Iri<'static> =
    iri!("https://w3id.org/security#RsaVerificationKey2018");

/// RSA verification key 2018.
///
/// To be used with the [RSA Signature Suite 2018][1].
///
/// See: <https://www.w3.org/TR/did-spec-registries/#rsaverificationkey2018>
///
/// [1]: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "RsaVerificationKey2018")]
pub struct RsaVerificationKey2018 {
    /// Key identifier.
    pub id: IriBuf,

    /// Key crontroller.
    pub controller: IriBuf, // TODO: should be an URI.

    /// Public JSON Web Key.
    #[serde(rename = "publicKeyJwk")]
    pub public_key: Box<JWK>,
}

impl RsaVerificationKey2018 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<String, SignatureError> {
        let header = ssi_jws::Header::new_detached(ssi_jwk::Algorithm::RS256, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(ssi_jwk::Algorithm::RS256, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(multibase::Base::Base64.encode(signature))
    }

    pub fn try_import_signature(signature: crate::Signature) -> Result<String, VerificationError> {
        match signature {
            crate::Signature::Base64(s) => Ok(s),
            _ => Err(VerificationError::InvalidSignature),
        }
    }

    pub fn try_import_signature_ref(
        signature: crate::SignatureRef,
    ) -> Result<&str, VerificationError> {
        match signature {
            crate::SignatureRef::Base64(s) => Ok(s),
            _ => Err(VerificationError::InvalidSignature),
        }
    }

    pub fn export_signature_ref(signature: &str) -> crate::SignatureRef {
        crate::SignatureRef::Base64(signature)
    }
}

impl ssi_crypto::VerificationMethod for RsaVerificationKey2018 {
    type Reference<'a> = &'a Self;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    // Base64 signature.
    type Signature = String;

    type SignatureRef<'a> = &'a str;

    fn signature_reference(signature: &Self::Signature) -> Self::SignatureRef<'_> {
        signature
    }
}

impl VerificationMethod for RsaVerificationKey2018 {
    /// Returns the identifier of the key.
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn expected_type() -> Option<String> {
        Some(RSA_VERIFICATION_KEY_2018_TYPE.to_string())
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        RSA_VERIFICATION_KEY_2018_TYPE
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }
}

#[async_trait]
impl<'a> VerificationMethodRef<'a, RsaVerificationKey2018> for &'a RsaVerificationKey2018 {
    /// Verifies the given signature.
    async fn verify<'s: 'async_trait>(
        self,
        controllers: &impl crate::ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: &'s str,
    ) -> Result<bool, VerificationError> {
        controllers
            .ensure_allows_verification_method(
                self.controller.as_iri(),
                self.id.as_iri(),
                proof_purpose,
            )
            .await?;

        let signature_bytes = multibase::Base::Base64
            .decode(signature)
            .map_err(|_| VerificationError::InvalidProof)?;

        let header = ssi_jws::Header::new_detached(ssi_jwk::Algorithm::RS256, None);
        let jws_signing_bytes = header.encode_signing_bytes(&signing_bytes);

        match self.public_key.algorithm.as_ref() {
            Some(ssi_jwk::Algorithm::RS256) => Ok(ssi_jws::verify_bytes(
                ssi_jwk::Algorithm::RS256,
                &jws_signing_bytes,
                &self.public_key,
                &signature_bytes,
            )
            .is_ok()),
            _ => Err(ssi_crypto::VerificationError::InvalidKey),
        }
    }
}

impl LinkedDataVerificationMethod for RsaVerificationKey2018 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(RSA_VERIFICATION_KEY_2018_IRI.into())),
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
            PUBLIC_KEY_JWK_IRI.into(),
            Object::Literal(Literal::new(
                serde_json::to_string(&self.public_key).unwrap(),
                literal::Type::Any(RDF_JSON.into()),
            )),
            None,
        ));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for RsaVerificationKey2018
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for RsaVerificationKey2018
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_JWK_IRI))),
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
