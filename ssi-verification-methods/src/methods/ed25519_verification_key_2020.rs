use std::hash::Hash;

use async_trait::async_trait;
use ed25519_dalek::Verifier;
use iref::{Iri, IriBuf};
use rand_core_0_5::{CryptoRng, RngCore};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use ssi_multicodec::MultiEncodedBuf;
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ControllerProvider, LinkedDataVerificationMethod, VerificationMethod, CONTROLLER_IRI,
    MULTIBASE_IRI, PUBLIC_KEY_MULTIBASE_IRI, RDF_TYPE_IRI,
};

/// IRI of the Ed25519 Verification Key 2020 type.
pub const ED25519_VERIFICATION_KEY_2020_IRI: Iri<'static> =
    iri!("https://w3id.org/security#Ed25519VerificationKey2020");

/// Ed25519 Verification Key 2020 type name.
pub const ED25519_VERIFICATION_KEY_2020_TYPE: &str = "Ed25519VerificationKey2020";

/// Deprecated verification method for the `Ed25519Signature2020` suite.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#ed25519verificationkey2020>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519VerificationKey2020 {
    /// Key identifier.
    pub id: IriBuf,

    /// Controller of the verification method.
    pub controller: IriBuf,

    /// Public key encoded according to [MULTICODEC] and formatted according to
    /// [MULTIBASE].
    ///
    /// The multicodec encoding of an Ed25519 public key is the
    /// two-byte prefix 0xed01 followed by the 32-byte public key data. The 34
    /// byte value is then encoded using base58-btc (z) as the prefix. Any other
    /// encoding MUST NOT be allowed.
    pub public_key_multibase: String,
}

impl Ed25519VerificationKey2020 {
    pub fn generate_key_pair(
        id: IriBuf,
        controller: IriBuf,
        csprng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, ed25519_dalek::SecretKey) {
        let key = ed25519_dalek::Keypair::generate(csprng);
        (
            Self::from_public_key(id, controller, key.public),
            key.secret,
        )
    }

    pub fn from_public_key(
        id: IriBuf,
        controller: IriBuf,
        public_key: ed25519_dalek::PublicKey,
    ) -> Self {
        let bytes = public_key.to_bytes();
        let multi_encoded = MultiEncodedBuf::encode(ssi_multicodec::ED25519_PUB, &bytes);

        Self {
            id,
            controller,
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                multi_encoded.as_bytes(),
            ),
        }
    }
}

#[async_trait]
impl VerificationMethod for Ed25519VerificationKey2020 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }

    fn type_(&self) -> &str {
        ED25519_VERIFICATION_KEY_2020_TYPE
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
        let pk_multi_encoded = MultiEncodedBuf::new(
            multibase::decode(&self.public_key_multibase)
                .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?
                .1,
        )
        .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::ED25519_PUB {
            let pk = ed25519_dalek::PublicKey::from_bytes(pk_data)
                .map_err(|_| ssi_crypto::VerificationError::InvalidKey)?;
            let signature = ed25519_dalek::Signature::from_bytes(signature)
                .map_err(|_| ssi_crypto::VerificationError::InvalidSignature)?;
            Ok(pk.verify(signing_bytes, &signature).is_ok())
        } else {
            Err(ssi_crypto::VerificationError::InvalidKey)
        }
    }
}

impl LinkedDataVerificationMethod for Ed25519VerificationKey2020 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(ED25519_VERIFICATION_KEY_2020_IRI.into())),
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

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for Ed25519VerificationKey2020
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for Ed25519VerificationKey2020
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
