use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_security::{BLOCKCHAIN_ACCOUNT_ID, PUBLIC_KEY_JWK};
use static_iref::iri;
use std::hash::Hash;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    covariance_rule, ExpectedType, LinkedDataVerificationMethod, Referencable,
    TypedVerificationMethod, VerificationError, VerificationMethod, CONTROLLER_IRI, RDF_JSON,
    RDF_TYPE_IRI, XSD_STRING,
};

pub const TEZOS_METHOD_2021_IRI: Iri<'static> = iri!("https://w3id.org/security#TezosMethod2021");

pub const TEZOS_METHOD_2021_TYPE: &str = "TezosMethod2021";

/// `TezosMethod2021` Verification Method.
///
/// # Signature algorithm
///
/// The signature algorithm must be either:
/// - EdBlake2b,
/// - ESBlake2bK,
/// - ESBlake2b
///
/// # Key format
///
/// The public key is either stored using the `publicKeyJwk` or
/// `blockchainAccountId` properties. Because `blockchainAccountId` is just a
/// hash of the key, the public key must be embedded in the proof and passed to
/// the verification method (as its context).
///
/// In the proof, the public must be stored using the `publicKeyJwk` or
/// `publicKeyMultibase` properties. Here `publicKeyMultibase` is used in a
/// non-standard way, where the public key is encoded in base58 (`z` prefix) as
/// a thezos key (so without multicodec, contrarily to the specification).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "TezosMethod2021")]
pub struct TezosMethod2021 {
    /// Key identifier.
    pub id: IriBuf,

    /// Controller of the verification method.
    pub controller: IriBuf,

    #[serde(flatten)]
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "blockchainAccountId")]
    BlockchainAccountId(ssi_caips::caip10::BlockchainAccountId),
}

impl PublicKey {
    pub fn matches(&self, other: &JWK) -> Result<bool, VerificationError> {
        use ssi_caips::caip10::BlockchainAccountIdVerifyError as VerifyError;
        match self {
            Self::Jwk(jwk) => Ok(jwk.equals_public(other)),
            Self::BlockchainAccountId(id) => match id.verify(other) {
                Err(VerifyError::UnknownChainId(_) | VerifyError::HashError(_)) => {
                    Err(VerificationError::InvalidKey)
                }
                Err(VerifyError::KeyMismatch(_, _)) => Ok(false),
                Ok(()) => Ok(true),
            },
        }
    }

    // pub fn sign(&self, data: &[u8]) {
    // 	// let (header, payload, signature_bytes) =
    //     //     jws.decode().map_err(|_| VerificationError::InvalidProof)?;

    //     // if !matches!(header.algorithm, Algorithm::EdBlake2b | Algorithm::ESBlake2b | Algorithm::ESBlake2bK) {
    //     //     return Err(VerificationError::InvalidProof);
    //     // }
    // }
}

impl Referencable for TezosMethod2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for TezosMethod2021 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for TezosMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(TEZOS_METHOD_2021_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        TEZOS_METHOD_2021_TYPE
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, TezosMethod2021, signature::Base58PublicKeyJwkOrMultibase> for &'a TezosMethod2021 {
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         signing_bytes: &[u8],
//         signature: signature::Base58PublicKeyJwkOrMultibaseRef<'s>
//     ) -> Result<bool, VerificationError> {
//         controllers
//             .ensure_allows_verification_method(
//                 self.controller.as_iri(),
//                 self.id.as_iri(),
//                 proof_purpose,
//             )
//             .await?;

//         let (algorithm, signature_bytes) = ssi_tzkey::decode_tzsig(signature.proof_value)
//             .map_err(|_| VerificationError::InvalidSignature)?;

//         let key = match signature.public_key.map(|k| k.as_jwk()).transpose()? {
//             Some(key) => {
//                 if !self.public_key.matches(&key)? {
//                     return Err(VerificationError::InvalidProof);
//                 }

//                 key
//             }
//             None => match &self.public_key {
//                 PublicKey::Jwk(key) => Cow::Borrowed(key.as_ref()),
//                 _ => return Err(VerificationError::MissingPublicKey),
//             },
//         };

//         Ok(ssi_jws::verify_bytes(algorithm, signing_bytes, &key, &signature_bytes).is_ok())
//     }
// }

impl LinkedDataVerificationMethod for TezosMethod2021 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(TEZOS_METHOD_2021_IRI.into())),
            None,
        ));

        quads.push(Quad(
            Id::Iri(self.id.clone()),
            CONTROLLER_IRI.into(),
            Object::Id(Id::Iri(self.controller.clone())),
            None,
        ));

        match &self.public_key {
            PublicKey::Jwk(jwk) => {
                quads.push(Quad(
                    Id::Iri(self.id.clone()),
                    PUBLIC_KEY_JWK.into(),
                    Object::Literal(Literal::new(
                        serde_json::to_string(jwk).unwrap(),
                        literal::Type::Any(RDF_JSON.into()),
                    )),
                    None,
                ));
            }
            PublicKey::BlockchainAccountId(account_id) => {
                quads.push(Quad(
                    Id::Iri(self.id.clone()),
                    BLOCKCHAIN_ACCOUNT_ID.into(),
                    Object::Literal(Literal::new(
                        account_id.to_string(),
                        literal::Type::Any(XSD_STRING.into()),
                    )),
                    None,
                ));
            }
        }

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for TezosMethod2021
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

        match self.public_key {
            PublicKey::Jwk(jwk) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_JWK))),
                    meta.clone(),
                );
                let key_value =
                    json_ld::Value::Json(json_syntax::to_value_with(jwk, || meta.clone()).unwrap());
                node.insert(
                    key_prop,
                    Meta(
                        json_ld::Indexed::new(json_ld::Object::Value(key_value), None),
                        meta.clone(),
                    ),
                );
            }
            PublicKey::BlockchainAccountId(account_id) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(BLOCKCHAIN_ACCOUNT_ID))),
                    meta.clone(),
                );
                let key_value = json_ld::Value::Literal(
                    json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                        account_id.to_string(),
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
            }
        }

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for TezosMethod2021
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

        match &self.public_key {
            PublicKey::Jwk(jwk) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_JWK))),
                    meta.clone(),
                );
                let key_value =
                    json_ld::Value::Json(json_syntax::to_value_with(jwk, || meta.clone()).unwrap());
                node.insert(
                    key_prop,
                    Meta(
                        json_ld::Indexed::new(json_ld::Object::Value(key_value), None),
                        meta.clone(),
                    ),
                );
            }
            PublicKey::BlockchainAccountId(account_id) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(BLOCKCHAIN_ACCOUNT_ID))),
                    meta.clone(),
                );
                let key_value = json_ld::Value::Literal(
                    json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                        account_id.to_string(),
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
            }
        }

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}
