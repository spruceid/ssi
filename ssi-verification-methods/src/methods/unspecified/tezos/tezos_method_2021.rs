use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::{algorithm::AnyBlake2b, JWK};
use static_iref::iri;
use std::{collections::BTreeMap, hash::Hash};

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SigningMethod, TypedVerificationMethod, VerificationError, VerificationMethod,
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
    pub fn verify_bytes(
        &self,
        public_key_jwk: Option<&JWK>,
        message: &[u8],
        algorithm: AnyBlake2b,
        signature: &[u8],
    ) -> Result<bool, VerificationError> {
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

    fn from_generic(
        properties: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, InvalidVerificationMethod> {
        match properties.get("publicKeyJwk") {
            Some(serde_json::Value::String(value)) => {
                Ok(Self::Jwk(Box::new(value.parse().map_err(|_| {
                    InvalidVerificationMethod::invalid_property("publicKeyJwk")
                })?)))
            }
            Some(_) => Err(InvalidVerificationMethod::invalid_property("publicKeyJwk")),
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
    ) -> Result<bool, VerificationError> {
        match self {
            Self::BlockchainAccountId(account_id) => match public_key_jwk {
                Some(jwk) => match account_id.verify(jwk) {
                    Ok(()) => Ok(
                        ssi_jws::verify_bytes(algorithm.into(), message, jwk, signature).is_ok(),
                    ),
                    Err(_) => Ok(false),
                },
                None => Err(VerificationError::MissingPublicKey),
            },
            Self::Jwk(jwk) => {
                Ok(ssi_jws::verify_bytes(algorithm.into(), message, jwk, signature).is_ok())
            }
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
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }

    fn ref_id<'a>(r: Self::Reference<'a>) -> &'a Iri {
        r.id.as_iri()
    }

    fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a Iri> {
        Some(r.controller.as_iri())
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

    fn ref_type<'a>(_r: Self::Reference<'a>) -> &'a str {
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
            Err(InvalidVerificationMethod::InvalidTypeName(value.type_))
        }
    }
}

impl SigningMethod<JWK, ssi_jwk::algorithm::AnyBlake2b> for TezosMethod2021 {
    fn sign_bytes_ref(
        _this: &Self,
        key: &JWK,
        algorithm: ssi_jwk::algorithm::AnyBlake2b,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm.into(), bytes, key)
            .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))
    }
}
