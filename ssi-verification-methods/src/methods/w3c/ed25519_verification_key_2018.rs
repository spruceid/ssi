use std::hash::Hash;

use async_trait::async_trait;
use ed25519_dalek::{Signer, Verifier};
use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_crypto::{SignatureError, VerificationError};
use ssi_jws::{CompactJWSStr, CompactJWSString};
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    signature, ControllerProvider, ExpectedType, LinkedDataVerificationMethod, NoContext,
    VerificationMethod, VerificationMethodRef, CONTROLLER_IRI, RDF_TYPE_IRI, XSD_STRING,
};

/// IRI of the Ed25519 Verification Key 2018 type.
pub const ED25519_VERIFICATION_KEY_2018_IRI: Iri<'static> =
    iri!("https://w3id.org/security#Ed25519VerificationKey2018");

/// Ed25519 Verification Key 2018 type name.
pub const ED25519_VERIFICATION_KEY_2018_TYPE: &str = "Ed25519VerificationKey2018";

pub const PUBLIC_KEY_BASE_58_IRI: Iri<'static> = iri!("https://w3id.org/security#publicKeyBase58");

/// Deprecated verification method for the `Ed25519Signature2018` suite.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/#the-ed25519-key-format>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "Ed25519VerificationKey2018")]
pub struct Ed25519VerificationKey2018 {
    /// Key identifier.
    pub id: IriBuf,

    /// Controller of the verification method.
    pub controller: IriBuf,

    /// Public key encoded in base58 using the same alphabet as Bitcoin
    /// addresses and IPFS hashes.
    #[serde(rename = "publicKeyBase58")]
    pub public_key_base58: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::SignatureError),
}

impl Ed25519VerificationKey2018 {
    pub fn decode_public_key(&self) -> Result<ed25519_dalek::PublicKey, InvalidPublicKey> {
        let pk_bytes = multibase::Base::Base58Btc.decode(&self.public_key_base58)?;
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk_bytes)?;
        Ok(pk)
    }

    pub fn sign(
        &self,
        data: &[u8],
        key_pair: &ed25519_dalek::Keypair,
    ) -> Result<CompactJWSString, SignatureError> {
        let header = ssi_jws::Header::new_detached(ssi_jwk::Algorithm::EdDSA, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = key_pair.sign(&signing_bytes);

        Ok(ssi_jws::CompactJWSString::from_signing_bytes_and_signature(
            signing_bytes,
            signature.to_bytes(),
        )
        .unwrap())
    }
}

impl ssi_crypto::VerificationMethod for Ed25519VerificationKey2018 {
    type Context<'c> = NoContext;

    type Reference<'a> = &'a Self;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    type Signature = signature::Jws;
}

impl VerificationMethod for Ed25519VerificationKey2018 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }

    fn expected_type() -> Option<ExpectedType> {
        Some(ED25519_VERIFICATION_KEY_2018_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        ED25519_VERIFICATION_KEY_2018_TYPE
    }
}

#[async_trait]
impl<'a> VerificationMethodRef<'a, Ed25519VerificationKey2018> for &'a Ed25519VerificationKey2018 {
    async fn verify<'c: 'async_trait, 's: 'async_trait>(
        self,
        controllers: &impl ControllerProvider,
        _: NoContext,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        jws: &'s CompactJWSStr,
    ) -> Result<bool, VerificationError> {
        controllers
            .ensure_allows_verification_method(
                self.controller.as_iri(),
                self.id.as_iri(),
                proof_purpose,
            )
            .await?;

        let (header, payload, signature_bytes) =
            jws.decode().map_err(|_| VerificationError::InvalidProof)?;

        if header.algorithm != ssi_jwk::Algorithm::EdDSA {
            return Err(VerificationError::InvalidProof);
        }

        if payload.as_ref() != signing_bytes {
            return Err(VerificationError::InvalidProof);
        }

        let pk = self
            .decode_public_key()
            .map_err(|_| VerificationError::InvalidKey)?;

        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
            .map_err(|_| ssi_crypto::VerificationError::InvalidSignature)?;
        Ok(pk.verify(signing_bytes, &signature).is_ok())
    }
}

impl LinkedDataVerificationMethod for Ed25519VerificationKey2018 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(ED25519_VERIFICATION_KEY_2018_IRI.into())),
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
            PUBLIC_KEY_BASE_58_IRI.into(),
            Object::Literal(Literal::new(
                self.public_key_base58.clone(),
                literal::Type::Any(XSD_STRING.into()),
            )),
            None,
        ));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for Ed25519VerificationKey2018
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_BASE_58_IRI))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.public_key_base58,
            )),
            Some(vocabulary.insert(XSD_STRING)),
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for Ed25519VerificationKey2018
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_BASE_58_IRI))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.public_key_base58.clone(),
            )),
            None,
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
