use std::hash::Hash;

use async_trait::async_trait;
use ed25519_dalek::Verifier;
use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ControllerProvider, LinkedDataVerificationMethod, VerificationMethod, CONTROLLER_IRI,
    RDF_TYPE_IRI, XSD_STRING,
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519VerificationKey2018 {
    /// Key identifier.
    id: IriBuf,

    /// Controller of the verification method.
    controller: IriBuf,

    /// Public key encoded in base58 using the same alphabet as Bitcoin
    /// addresses and IPFS hashes.
    public_key_base58: String,
}

#[async_trait]
impl VerificationMethod for Ed25519VerificationKey2018 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }

    fn type_(&self) -> &str {
        ED25519_VERIFICATION_KEY_2018_TYPE
    }

    async fn verify(
        &self,
        controllers: &impl ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, ssi_crypto::VerificationError> {
        controllers
            .ensure_allows_verification_method(
                self.controller.as_iri(),
                self.id.as_iri(),
                proof_purpose,
            )
            .await?;

        let pk_bytes = multibase::Base::Base58Btc
            .decode(&self.public_key_base58)
            .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
        let signature = ed25519_dalek::Signature::from_bytes(signature)
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
