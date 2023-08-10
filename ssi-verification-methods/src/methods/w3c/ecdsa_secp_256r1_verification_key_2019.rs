use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{MULTIBASE, PUBLIC_KEY_MULTIBASE};
use static_iref::iri;
use std::hash::Hash;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    covariance_rule, ExpectedType, LinkedDataVerificationMethod, Referencable,
    TypedVerificationMethod, VerificationError, VerificationMethod, CONTROLLER_IRI, RDF_TYPE_IRI,
};

pub const ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE: &str = "EcdsaSecp256r1VerificationKey2019";

pub const ECDSA_SECP_256R1_VERIFICATION_KEY_2019_IRI: Iri<'static> =
    iri!("https://w3id.org/security#EcdsaSecp256r1VerificationKey2019");

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Multicodec(#[from] ssi_multicodec::Error),

    #[error("invalid key type")]
    InvalidKeyType,

    #[error(transparent)]
    P256(#[from] p256::elliptic_curve::Error),
}

/// Key for [Ecdsa Secp256r1 Signature 2019][1].
///
/// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1verificationkey2019>
///
/// [1]: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "EcdsaSecp256r1VerificationKey2019")]
pub struct EcdsaSecp256r1VerificationKey2019 {
    /// Key identifier.
    pub id: IriBuf,

    /// Key controller.
    pub controller: IriBuf, // TODO: should be an URI.

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

impl EcdsaSecp256r1VerificationKey2019 {
    pub fn decode_public_key(&self) -> Result<p256::PublicKey, InvalidPublicKey> {
        let pk_multi_encoded =
            MultiEncodedBuf::new(multibase::decode(&self.public_key_multibase)?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::ES256 {
            let pk = p256::PublicKey::from_sec1_bytes(pk_data)?;
            Ok(pk)
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn sign(&self, data: &[u8], secret_key: &p256::SecretKey) -> String {
        use p256::ecdsa::signature::{Signature, Signer};
        let signing_key = p256::ecdsa::SigningKey::from(secret_key);
        let signature: p256::ecdsa::Signature = signing_key.try_sign(data).unwrap();

        multibase::encode(multibase::Base::Base58Btc, signature.as_bytes())
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        use p256::ecdsa::signature::Verifier;

        let public_key = self
            .decode_public_key()
            .map_err(|_| VerificationError::InvalidKey)?;
        let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);

        let signature = p256::ecdsa::Signature::try_from(signature_bytes)
            .map_err(|_| VerificationError::InvalidSignature)?;

        Ok(verifying_key.verify(data, &signature).is_ok())
    }
}

impl Referencable for EcdsaSecp256r1VerificationKey2019 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for EcdsaSecp256r1VerificationKey2019 {
    /// Returns the identifier of the key.
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for EcdsaSecp256r1VerificationKey2019 {
    fn expected_type() -> Option<ExpectedType> {
        Some(
            ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE
                .to_string()
                .into(),
        )
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, EcdsaSecp256r1VerificationKey2019, signature::Multibase>
//     for &'a EcdsaSecp256r1VerificationKey2019
// {
//     /// Verifies the given signature.
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl crate::ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         data: &[u8],
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

//         self.verify_bytes(data, &signature_bytes)
//     }
// }

impl LinkedDataVerificationMethod for EcdsaSecp256r1VerificationKey2019 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(ECDSA_SECP_256R1_VERIFICATION_KEY_2019_IRI.into())),
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

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M>
    for EcdsaSecp256r1VerificationKey2019
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M>
    for EcdsaSecp256r1VerificationKey2019
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
