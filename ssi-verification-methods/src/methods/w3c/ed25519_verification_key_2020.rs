use std::hash::Hash;

use ed25519_dalek::{Signer, Verifier};
use iref::{Iri, IriBuf};
use rand_core_0_5::{CryptoRng, RngCore};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{MULTIBASE, PUBLIC_KEY_MULTIBASE};
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    covariance_rule, ExpectedType, LinkedDataVerificationMethod, Referencable,
    TypedVerificationMethod, VerificationError, VerificationMethod, CONTROLLER_IRI, RDF_TYPE_IRI,
};

/// IRI of the Ed25519 Verification Key 2020 type.
pub const ED25519_VERIFICATION_KEY_2020_IRI: Iri<'static> =
    iri!("https://w3id.org/security#Ed25519VerificationKey2020");

/// Ed25519 Verification Key 2020 type name.
pub const ED25519_VERIFICATION_KEY_2020_TYPE: &str = "Ed25519VerificationKey2020";

/// Deprecated verification method for the `Ed25519Signature2020` suite.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#ed25519verificationkey2020>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "Ed25519VerificationKey2020")]
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
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Multicodec(#[from] ssi_multicodec::Error),

    #[error("invalid key type")]
    InvalidKeyType,

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::SignatureError),
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

    pub fn decode_public_key(&self) -> Result<ed25519_dalek::PublicKey, InvalidPublicKey> {
        let pk_multi_encoded =
            MultiEncodedBuf::new(multibase::decode(&self.public_key_multibase)?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::ED25519_PUB {
            let pk = ed25519_dalek::PublicKey::from_bytes(pk_data)?;
            Ok(pk)
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn sign_bytes(&self, data: &[u8], key_pair: &ed25519_dalek::Keypair) -> Vec<u8> {
        let signature = key_pair.sign(data);
        signature.to_bytes().to_vec()
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let pk = self
            .decode_public_key()
            .map_err(|_| VerificationError::InvalidKey)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
            .map_err(|_| VerificationError::InvalidSignature)?;
        Ok(pk.verify(data, &signature).is_ok())
    }
}

impl Referencable for Ed25519VerificationKey2020 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for Ed25519VerificationKey2020 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for Ed25519VerificationKey2020 {
    fn expected_type() -> Option<ExpectedType> {
        Some(ED25519_VERIFICATION_KEY_2020_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        ED25519_VERIFICATION_KEY_2020_TYPE
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, Ed25519VerificationKey2020, signature::Multibase> for &'a Ed25519VerificationKey2020 {
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         signing_bytes: &[u8],
//         signature: &'s str,
//     ) -> Result<bool, VerificationError> {
//         controllers
//             .ensure_allows_verification_method(
//                 self.controller.as_iri(),
//                 self.id.as_iri(),
//                 proof_purpose,
//             )
//             .await?;

//         let signature_bytes = multibase::decode(signature)
//             .map_err(|_| VerificationError::InvalidProof)?
//             .1;

//         self.verify_bytes(signing_bytes, &signature_bytes)
//     }
// }

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
            PUBLIC_KEY_MULTIBASE.into(),
            Object::Literal(Literal::new(
                self.public_key_multibase.clone(),
                literal::Type::Any(MULTIBASE.into()),
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_MULTIBASE))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.public_key_multibase,
            )),
            Some(vocabulary.insert(MULTIBASE)),
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_MULTIBASE))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.public_key_multibase.clone(),
            )),
            Some(vocabulary.insert(MULTIBASE)),
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
