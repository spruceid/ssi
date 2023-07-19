use std::hash::Hash;

use async_trait::async_trait;
use ed25519_dalek::Verifier;
use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use ssi_multicodec::MultiEncodedBuf;
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ControllerProvider, LinkedDataVerificationMethod, VerificationMethod, CONTROLLER_IRI,
    RDF_TYPE_IRI,
};

pub const MULTIBASE_IRI: Iri<'static> = iri!("https://w3id.org/security#multibase");

pub const MULTIKEY_IRI: Iri<'static> = iri!("https://w3id.org/security#Multikey"); // TODO: find the definition in the specs.

pub const MULTIKEY_TYPE: &str = "Multikey";

pub const PUBLIC_KEY_MULTIBASE_IRI: Iri<'static> =
    iri!("https://w3id.org/security#publicKeyMultibase");

/// Multikey verification method.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#multikey>.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mulitkey {
    /// Key identifier.
    id: IriBuf,

    /// Controller of the verification method.
    controller: IriBuf,

    /// Public key.
    public_key_multibase: String,
}

#[async_trait]
impl VerificationMethod for Mulitkey {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }

    fn type_(&self) -> &str {
        MULTIKEY_TYPE
    }

    async fn verify(
        &self,
        controllers: &impl ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, ssi_crypto::VerificationError> {
        // Check proof purpose.
        controllers
            .ensure_allows_verification_method(
                self.controller.as_iri(),
                self.id.as_iri(),
                proof_purpose,
            )
            .await?;

        // Decode key.
        let pk_multi_encoded = MultiEncodedBuf::new(
            multibase::decode(&self.public_key_multibase)
                .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?
                .1,
        )
        .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();

        match pk_codec {
            #[cfg(any(feature = "ed25519"))]
            ssi_multicodec::ED25519_PUB => {
                let pk = ed25519_dalek::PublicKey::from_bytes(pk_data)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
                let signature = ed25519_dalek::Signature::from_bytes(signature)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidSignature)?;
                Ok(pk.verify(signing_bytes, &signature).is_ok())
            }
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => {
                let public_key = k256::PublicKey::from_sec1_bytes(pk_data)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let signature = k256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidSignature)?;

                Ok(verifying_key.verify(signing_bytes, &signature).is_ok())
            }
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => {
                let public_key = p256::PublicKey::from_sec1_bytes(pk_data)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let signature = p256::ecdsa::Signature::try_from(signature)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidSignature)?;

                Ok(verifying_key.verify(signing_bytes, &signature).is_ok())
            }
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => {
                let public_key = p384::PublicKey::from_sec1_bytes(pk_data)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
                let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
                let signature = p384::ecdsa::Signature::try_from(signature)
                    .map_err(|_| ssi_crypto::VerificationError::InvalidSignature)?;

                Ok(verifying_key.verify(signing_bytes, &signature).is_ok())
            }
            _ => Err(ssi_crypto::VerificationError::InvalidKey),
        }
    }
}

impl LinkedDataVerificationMethod for Mulitkey {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(MULTIKEY_IRI.into())),
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
            PUBLIC_KEY_MULTIBASE_IRI.into(),
            Object::Literal(Literal::new(
                self.public_key_multibase.clone(),
                literal::Type::Any(MULTIBASE_IRI.into()),
            )),
            None,
        ));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for Mulitkey
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn into_json_ld_object_meta(
        self,
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_MULTIBASE_IRI))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.public_key_multibase,
            )),
            Some(vocabulary.insert(MULTIBASE_IRI)),
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for Mulitkey
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_MULTIBASE_IRI))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.public_key_multibase.clone(),
            )),
            Some(vocabulary.insert(MULTIBASE_IRI)),
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
