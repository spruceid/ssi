use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_crypto::algorithm::AnyBlake2b;
use ssi_jwk::JWK;
use ssi_verification_methods_core::VerificationMethodSet;
use static_iref::iri;
use std::{collections::BTreeMap, hash::Hash};

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, SigningMethod,
    TypedVerificationMethod, VerificationMethod,
};

pub const TEZOS_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#TezosMethod2021");

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
/// a tezos key (so without multicodec, contrarily to the specification).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[serde(tag = "type", rename = "TezosMethod2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct TezosMethod2021 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    #[serde(flatten)]
    #[ld(flatten)]
    pub public_key: PublicKey,
}

impl TezosMethod2021 {
    pub const NAME: &'static str = TEZOS_METHOD_2021_TYPE;
    pub const IRI: &'static Iri = TEZOS_METHOD_2021_IRI;

    pub fn public_key_jwk(&self) -> Option<&JWK> {
        self.public_key.as_jwk()
    }

    pub fn verify_bytes(
        &self,
        public_key_jwk: Option<&JWK>,
        message: &[u8],
        algorithm: AnyBlake2b,
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        self.public_key
            .verify_bytes(public_key_jwk, message, algorithm, signature)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "blockchainAccountId")]
    #[ld("sec:blockchainAccountId")]
    BlockchainAccountId(ssi_caips::caip10::BlockchainAccountId),
}

impl PublicKey {
    pub fn as_jwk(&self) -> Option<&JWK> {
        match self {
            Self::Jwk(jwk) => Some(jwk),
            Self::BlockchainAccountId(_) => None,
        }
    }

    pub fn matches(&self, other: &JWK) -> Result<bool, ProofValidationError> {
        use ssi_caips::caip10::BlockchainAccountIdVerifyError as VerifyError;
        match self {
            Self::Jwk(jwk) => Ok(jwk.equals_public(other)),
            Self::BlockchainAccountId(id) => match id.verify(other) {
                Err(VerifyError::UnknownChainId(_) | VerifyError::HashError(_)) => {
                    Err(ProofValidationError::InvalidKey)
                }
                Err(VerifyError::KeyMismatch(_, _)) => Ok(false),
                Ok(()) => Ok(true),
            },
        }
    }

    fn from_generic(
        properties: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, InvalidVerificationMethod> {
        match properties.get("publicKeyJwk") {
            Some(value) => Ok(Self::Jwk(Box::new(
                serde_json::from_value(value.clone())
                    .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?,
            ))),
            None => match properties.get("blockchainAccountId") {
                Some(serde_json::Value::String(value)) => {
                    Ok(Self::BlockchainAccountId(value.parse().map_err(|_| {
                        InvalidVerificationMethod::invalid_property("blockchainAccountId")
                    })?))
                }
                Some(_) => Err(InvalidVerificationMethod::invalid_property(
                    "blockchainAccountId",
                )),
                None => Err(InvalidVerificationMethod::missing_property("publicKeyJwk")),
            },
        }
    }

    pub fn verify_bytes(
        &self,
        public_key_jwk: Option<&JWK>,
        message: &[u8],
        algorithm: AnyBlake2b,
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        match self {
            Self::BlockchainAccountId(account_id) => match public_key_jwk {
                Some(jwk) => match account_id.verify(jwk) {
                    Ok(()) => Ok(
                        ssi_jws::verify_bytes(algorithm.into(), message, jwk, signature)
                            .map_err(|_| InvalidProof::Signature),
                    ),
                    Err(_) => Ok(Err(InvalidProof::KeyMismatch)),
                },
                None => Err(ProofValidationError::MissingPublicKey),
            },
            Self::Jwk(jwk) => Ok(
                ssi_jws::verify_bytes(algorithm.into(), message, jwk, signature)
                    .map_err(|_| InvalidProof::Signature),
            ),
        }
    }

    pub fn sign_bytes(
        &self,
        key: &JWK,
        algorithm: ssi_crypto::algorithm::AnyBlake2b,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm.into(), bytes, key)
            .map_err(MessageSignatureError::signature_failed)
    }
}

impl VerificationMethod for TezosMethod2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for TezosMethod2021 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for TezosMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(TEZOS_METHOD_2021_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == TEZOS_METHOD_2021_TYPE
    }

    fn type_(&self) -> &str {
        TEZOS_METHOD_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for TezosMethod2021 {
    type Error = InvalidVerificationMethod;

    fn try_from(value: GenericVerificationMethod) -> Result<Self, Self::Error> {
        if value.type_ == TEZOS_METHOD_2021_TYPE {
            Ok(Self {
                id: value.id,
                controller: value.controller,
                public_key: PublicKey::from_generic(&value.properties)?,
            })
        } else {
            Err(InvalidVerificationMethod::invalid_type_name(
                &value.type_,
                TEZOS_METHOD_2021_TYPE,
            ))
        }
    }
}

impl SigningMethod<JWK, ssi_crypto::algorithm::AnyBlake2b> for TezosMethod2021 {
    fn sign_bytes(
        &self,
        key: &JWK,
        algorithm: ssi_crypto::algorithm::AnyBlake2b,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm.into(), bytes, key)
            .map_err(MessageSignatureError::signature_failed)
    }
}
