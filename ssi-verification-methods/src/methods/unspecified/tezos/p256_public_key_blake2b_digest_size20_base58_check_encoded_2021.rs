use std::hash::Hash;

use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_security::BLOCKCHAIN_ACCOUNT_ID;
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ExpectedType, LinkedDataVerificationMethod,
    VerificationMethod, CONTROLLER_IRI,
    RDF_TYPE_IRI, XSD_STRING, VerificationError, Referencable,
};

pub const P256_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_IRI: Iri<'static> =
    iri!("https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021");

pub const P256_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE: &str =
    "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename = "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
)]
pub struct P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    /// Key identifier.
    pub id: IriBuf,

    /// Controller of the verification method.
    pub controller: IriBuf,

    /// Blockchain account id.
    #[serde(rename = "blockchainAccountId")]
    pub blockchain_account_id: ssi_caips::caip10::BlockchainAccountId,
}

impl P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    pub fn matches_public_key(&self, public_key: &JWK) -> Result<bool, VerificationError> {
        use ssi_caips::caip10::BlockchainAccountIdVerifyError as VerifyError;
        match self.blockchain_account_id.verify(public_key) {
            Err(VerifyError::UnknownChainId(_) | VerifyError::HashError(_)) => {
                Err(VerificationError::InvalidKey)
            }
            Err(VerifyError::KeyMismatch(_, _)) => Ok(false),
            Ok(()) => Ok(true),
        }
    }
}

impl Referencable for P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    type Reference<'a> = &'a Self where Self: 'a;
    
    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }
}

impl VerificationMethod for P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }

    fn expected_type() -> Option<ExpectedType> {
        Some(
            P256_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE
                .to_string()
                .into(),
        )
    }

    fn type_(&self) -> &str {
        P256_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, signature::JwsPublicKeyJwk>
//     for &'a P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
// {
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         signing_bytes: &[u8],
//         signature: signature::JwsPublicKeyJwkRef<'s>
//     ) -> Result<bool, VerificationError> {
//         controllers
//             .ensure_allows_verification_method(
//                 self.controller.as_iri(),
//                 self.id.as_iri(),
//                 proof_purpose,
//             )
//             .await?;

//         let (header, payload, signature_bytes) =
//             signature.jws.decode().map_err(|_| VerificationError::InvalidProof)?;

//         if header.algorithm != ssi_jwk::Algorithm::ESBlake2b {
//             return Err(VerificationError::InvalidProof);
//         }

//         if payload.as_ref() != signing_bytes {
//             return Err(VerificationError::InvalidProof);
//         }

//         if !self.matches_public_key(signature.public_key_jwk)? {
//             return Err(VerificationError::InvalidProof);
//         }

//         Ok(ssi_jws::verify_bytes(
//             ssi_jwk::Algorithm::ESBlake2b,
//             signature.jws.signing_bytes(),
//             signature.public_key_jwk,
//             &signature_bytes,
//         )
//         .is_ok())
//     }
// }

impl LinkedDataVerificationMethod for P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(
                P256_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_IRI.into(),
            )),
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
            BLOCKCHAIN_ACCOUNT_ID.into(),
            Object::Literal(Literal::new(
                self.blockchain_account_id.to_string(),
                literal::Type::Any(XSD_STRING.into()),
            )),
            None,
        ));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M>
    for P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(BLOCKCHAIN_ACCOUNT_ID))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.blockchain_account_id.to_string(),
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M>
    for P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
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
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(BLOCKCHAIN_ACCOUNT_ID))),
            meta.clone(),
        );
        let key_value = json_ld::Value::Literal(
            json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                self.blockchain_account_id.to_string(),
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