use std::{borrow::Cow, hash::Hash};

use async_trait::async_trait;
use hex::FromHexError;
use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_crypto::{SignatureError, VerificationError};
use ssi_jwk::JWK;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    LinkedDataVerificationMethod, VerificationMethod, VerificationMethodRef, CONTROLLER_IRI,
    PUBLIC_KEY_HEX_IRI, PUBLIC_KEY_JWK_IRI, RDF_JSON, RDF_TYPE_IRI, XSD_STRING,
};

pub const ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE: &str = "EcdsaSecp256k1VerificationKey2019";

pub const ECDSA_SECP_256K1_VERIFICATION_KEY_2019_IRI: Iri<'static> =
    iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019");

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "publicKeyHex")]
    Hex(String),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] FromHexError),

    #[error("invalid key bytes: {0}")]
    K256(#[from] k256::elliptic_curve::Error),
}

impl PublicKey {
    pub fn jwk(&self) -> Result<Cow<JWK>, InvalidPublicKey> {
        match self {
            Self::Jwk(jwk) => Ok(Cow::Borrowed(&*jwk)),
            Self::Hex(hex_encoded) => {
                let bytes = hex::decode(hex_encoded)?;
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

                Ok(Cow::Owned(jwk))
            }
        }
    }
}

/// Key for [Ecdsa Secp256k1 Signature 2019][1].
///
/// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/#key-format>
///
/// [1]: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "EcdsaSecp256k1VerificationKey2019")]
pub struct EcdsaSecp256k1VerificationKey2019 {
    /// Key identifier.
    pub id: IriBuf,

    /// Key controller.
    pub controller: IriBuf, // TODO: should be an URI.

    /// Public key.
    #[serde(flatten)]
    pub public_key: PublicKey,
}

impl EcdsaSecp256k1VerificationKey2019 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<CompactJWSString, SignatureError> {
        let algorithm = secret_key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256K);
        if algorithm != ssi_jwk::Algorithm::ES256K {
            return Err(SignatureError::InvalidSecretKey);
        }

        let header = ssi_jws::Header::new_detached(algorithm, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(algorithm, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn try_import_signature(
        signature: crate::Signature,
    ) -> Result<CompactJWSString, VerificationError> {
        match signature {
            crate::Signature::JWS(jws) => Ok(jws),
            _ => Err(VerificationError::InvalidSignature),
        }
    }

    pub fn try_import_signature_ref(
        signature: crate::SignatureRef,
    ) -> Result<&CompactJWSStr, VerificationError> {
        match signature {
            crate::SignatureRef::JWS(jws) => Ok(jws),
            _ => Err(VerificationError::InvalidSignature),
        }
    }

    pub fn export_signature_ref(signature: &CompactJWSStr) -> crate::SignatureRef {
        crate::SignatureRef::JWS(signature)
    }
}

impl ssi_crypto::VerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    type Reference<'a> = &'a Self;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    type Signature = CompactJWSString;

    type SignatureRef<'a> = &'a CompactJWSStr;

    fn signature_reference(signature: &Self::Signature) -> Self::SignatureRef<'_> {
        signature
    }
}

impl VerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    /// Returns the identifier of the key.
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn expected_type() -> Option<String> {
        Some(ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE.to_string())
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Iri {
        self.controller.as_iri()
    }
}

#[async_trait]
impl<'a> VerificationMethodRef<'a, EcdsaSecp256k1VerificationKey2019>
    for &'a EcdsaSecp256k1VerificationKey2019
{
    /// Verifies the given signature.
    async fn verify<'s: 'async_trait>(
        self,
        controllers: &impl crate::ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        data: &[u8],
        jws: &'s CompactJWSStr,
    ) -> Result<bool, VerificationError> {
        controllers
            .ensure_allows_verification_method(
                self.controller.as_iri(),
                self.id.as_iri(),
                proof_purpose,
            )
            .await?;

        let (_, payload, signature_bytes) =
            jws.decode().map_err(|_| VerificationError::InvalidProof)?;

        if payload.as_ref() != data {
            return Err(VerificationError::InvalidProof);
        }

        let public_key = self
            .public_key
            .jwk()
            .map_err(|_| VerificationError::InvalidKey)?;
        if public_key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256K) != ssi_jwk::Algorithm::ES256K
        {
            return Err(VerificationError::InvalidKey);
        }

        Ok(ssi_jws::verify_bytes(
            ssi_jwk::Algorithm::ES256K,
            jws.signing_bytes(),
            &public_key,
            &signature_bytes,
        )
        .is_ok())
    }
}

impl LinkedDataVerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(ECDSA_SECP_256K1_VERIFICATION_KEY_2019_IRI.into())),
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
                    PUBLIC_KEY_JWK_IRI.into(),
                    Object::Literal(Literal::new(
                        serde_json::to_string(jwk).unwrap(),
                        literal::Type::Any(RDF_JSON.into()),
                    )),
                    None,
                ));
            }
            PublicKey::Hex(hex) => {
                quads.push(Quad(
                    Id::Iri(self.id.clone()),
                    PUBLIC_KEY_HEX_IRI.into(),
                    Object::Literal(Literal::new(
                        hex.clone(),
                        literal::Type::Any(XSD_STRING.into()),
                    )),
                    None,
                ));
            }
        }

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M>
    for EcdsaSecp256k1VerificationKey2019
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
    for EcdsaSecp256k1VerificationKey2019
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
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_JWK_IRI))),
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
            PublicKey::Hex(hex) => {
                let key_prop = Meta(
                    json_ld::Id::Valid(Id::Iri(vocabulary.insert(PUBLIC_KEY_HEX_IRI))),
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
        }

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}
