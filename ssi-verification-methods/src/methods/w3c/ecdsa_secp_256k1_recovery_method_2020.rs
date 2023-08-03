use async_trait::async_trait;
use hex::FromHexError;
use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_security::{BLOCKCHAIN_ACCOUNT_ID, ETHEREUM_ADDRESS, PUBLIC_KEY_HEX, PUBLIC_KEY_JWK};
use static_iref::iri;
use std::hash::Hash;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ExpectedType, LinkedDataVerificationMethod, VerificationMethod,
    CONTROLLER_IRI, RDF_JSON, RDF_TYPE_IRI, XSD_STRING, signature, SignatureError, VerificationError,
};

pub const ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE: &str = "EcdsaSecp256k1RecoveryMethod2020";

pub const ECDSA_SECP_256K1_RECOVERY_METHOD_2020_IRI: Iri<'static> =
    iri!("https://w3id.org/security#EcdsaSecp256k1RecoveryMethod2020");

/// EcdsaSecp256k1RecoveryMethod2020 verification method.
///
/// See: <https://w3c-ccg.github.io/security-vocab/#EcdsaSecp256k1RecoveryMethod2020>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "EcdsaSecp256k1RecoveryMethod2020")]
pub struct EcdsaSecp256k1RecoveryMethod2020 {
    /// Key identifier.
    pub id: IriBuf,

    /// Key controller.
    pub controller: IriBuf, // TODO: should be an URI.

    /// Public key.
    #[serde(flatten)]
    pub public_key: PublicKey,
}

impl VerificationMethod for EcdsaSecp256k1RecoveryMethod2020 {
    /// Returns the identifier of the key.
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn expected_type() -> Option<ExpectedType> {
        Some(
            ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE
                .to_string()
                .into(),
        )
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }
}

impl EcdsaSecp256k1RecoveryMethod2020 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<CompactJWSString, SignatureError> {
        let algorithm = secret_key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256KR);
        if algorithm != ssi_jwk::Algorithm::ES256KR {
            return Err(SignatureError::InvalidSecretKey);
        }

        let header = ssi_jws::Header::new_detached(algorithm, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(algorithm, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature: &[u8]
    ) -> Result<bool, VerificationError> {
        // Recover the key used to sign the message.
        let key = ssi_jws::recover(ssi_jwk::Algorithm::ES256KR, data, signature)
            .map_err(|_| VerificationError::InvalidSignature)?;

        // Check the validity of the signing key.
        let matching_keys = self
            .public_key
            .matches(&key)
            .map_err(|_| VerificationError::InvalidProof)?;
        let algorithm = key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256KR);
        if !matching_keys || algorithm != ssi_jwk::Algorithm::ES256KR {
            return Err(VerificationError::InvalidKey);
        }

        // Verify the signature.
        Ok(ssi_jws::verify_bytes(
            ssi_jwk::Algorithm::ES256KR,
            data,
            &key,
            signature,
        )
        .is_ok())
    }
}

// #[async_trait]
// impl<'a> VerificationMethodRef<'a, EcdsaSecp256k1RecoveryMethod2020, signature::Jws>
//     for &'a EcdsaSecp256k1RecoveryMethod2020
// {
//     /// Verifies the given signature.
//     async fn verify<'s: 'async_trait>(
//         self,
//         controllers: &impl crate::ControllerProvider,
//         proof_purpose: ssi_crypto::ProofPurpose,
//         data: &[u8],
//         jws: &'s CompactJWSStr,
//     ) -> Result<bool, VerificationError> {
//         // Check that this verification method is authorized for the given
//         // proof purpose.
//         controllers
//             .ensure_allows_verification_method(
//                 self.controller.as_iri(),
//                 self.id.as_iri(),
//                 proof_purpose,
//             )
//             .await?;

//         // Decode the JWK.
//         let (header, payload, signature_bytes) =
//             jws.decode().map_err(|_| VerificationError::InvalidProof)?;

//         // Ensure the signed message matches the verified message.
//         if payload.as_ref() != data {
//             return Err(VerificationError::InvalidProof);
//         }

//         self.verify_bytes(jws.signing_bytes(), &signature_bytes)
//     }
// }

impl LinkedDataVerificationMethod for EcdsaSecp256k1RecoveryMethod2020 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(ECDSA_SECP_256K1_RECOVERY_METHOD_2020_IRI.into())),
            None,
        ));

        quads.push(Quad(
            Id::Iri(self.id.clone()),
            CONTROLLER_IRI.into(),
            Object::Id(Id::Iri(self.controller.clone())),
            None,
        ));

        self.public_key.quads(quads, Id::Iri(self.id.clone()));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M>
    for EcdsaSecp256k1RecoveryMethod2020
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for EcdsaSecp256k1RecoveryMethod2020
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

        self.public_key
            .as_json_ld(vocabulary, &mut node, meta.clone());

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "publicKeyHex")]
    Hex(String),

    #[serde(rename = "ethereumAddress")]
    EthereumAddress(ssi_security::EthereumAddressBuf),

    #[serde(rename = "blockchainAccountId")]
    BlockchainAccountId(ssi_caips::caip10::BlockchainAccountId),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] FromHexError),

    #[error("invalid key bytes: {0}")]
    K256(#[from] k256::elliptic_curve::Error),

    #[error("invalid key parameters")]
    InvalidParams,

    #[error("unknown chain id `{0}`")]
    UnknownChainId(String),

    #[error("unable to hash public key `{0}`")]
    HashError(String),
}

impl From<InvalidPublicKey> for VerificationError {
    fn from(_value: InvalidPublicKey) -> Self {
        Self::InvalidKey
    }
}

impl PublicKey {
    pub fn matches(&self, other: &JWK) -> Result<bool, InvalidPublicKey> {
        match self {
            Self::Jwk(jwk) => Ok(jwk.equals_public(other)),
            Self::Hex(hex) => {
                let bytes = hex::decode(hex)?;
                let pk = k256::PublicKey::from_sec1_bytes(&bytes)?;
                let jwk = JWK {
                    params: ssi_jwk::Params::EC(ssi_jwk::ECParams::try_from(&pk).unwrap()),
                    public_key_use: None,
                    key_operations: None,
                    algorithm: None,
                    key_id: None,
                    x509_url: None,
                    x509_certificate_chain: None,
                    x509_thumbprint_sha1: None,
                    x509_thumbprint_sha256: None,
                };

                Ok(jwk.equals_public(other))
            }
            Self::EthereumAddress(a) => {
                let ssi_jwk::Params::EC(params) = &other.params else {
					return Err(InvalidPublicKey::InvalidParams)
				};

                let pk: k256::PublicKey = params
                    .try_into()
                    .map_err(|_| InvalidPublicKey::InvalidParams)?;
                let b = ssi_crypto::hashes::keccak::hash_public_key(&pk);
                Ok(a.as_str() == b.as_str())
            }
            Self::BlockchainAccountId(id) => {
                use ssi_caips::caip10::BlockchainAccountIdVerifyError as VerifyError;

                match id.verify(other) {
                    Err(VerifyError::UnknownChainId(name)) => {
                        Err(InvalidPublicKey::UnknownChainId(name))
                    }
                    Err(VerifyError::HashError(e)) => Err(InvalidPublicKey::HashError(e)),
                    Err(VerifyError::KeyMismatch(_, _)) => Ok(false),
                    Ok(()) => Ok(true),
                }
            }
        }
    }

    fn quads(&self, quads: &mut Vec<Quad>, id: Id) {
        match self {
            Self::Jwk(jwk) => quads.push(Quad(
                id,
                PUBLIC_KEY_JWK.into(),
                Object::Literal(Literal::new(
                    serde_json::to_string(jwk).unwrap(),
                    literal::Type::Any(RDF_JSON.into()),
                )),
                None,
            )),
            Self::Hex(hex) => quads.push(Quad(
                id,
                PUBLIC_KEY_HEX.into(),
                Object::Literal(Literal::new(
                    hex.clone(),
                    literal::Type::Any(XSD_STRING.into()),
                )),
                None,
            )),
            Self::EthereumAddress(addr) => quads.push(Quad(
                id,
                ETHEREUM_ADDRESS.into(),
                Object::Literal(Literal::new(
                    addr.to_string(),
                    literal::Type::Any(XSD_STRING.into()),
                )),
                None,
            )),
            Self::BlockchainAccountId(account_id) => quads.push(Quad(
                id,
                BLOCKCHAIN_ACCOUNT_ID.into(),
                Object::Literal(Literal::new(
                    account_id.to_string(),
                    literal::Type::Any(XSD_STRING.into()),
                )),
                None,
            )),
        }
    }

    fn as_json_ld<V, M>(
        &self,
        vocabulary: &mut V,
        node: &mut json_ld::Node<V::Iri, V::BlankId, M>,
        meta: M,
    ) where
        V: VocabularyMut,
        V::Iri: Eq + Hash,
        V::BlankId: Eq + Hash,
        M: Clone,
    {
        match self {
            Self::Jwk(jwk) => {
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
                        meta,
                    ),
                );
            }
            Self::Hex(hex) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_HEX))),
                    meta.clone(),
                );
                let key_value = json_ld::Value::Literal(
                    json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                        hex.clone(),
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
            Self::EthereumAddress(addr) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(ETHEREUM_ADDRESS))),
                    meta.clone(),
                );
                let key_value = json_ld::Value::Literal(
                    json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                        addr.to_string(),
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
            Self::BlockchainAccountId(account_id) => {
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
    }
}
