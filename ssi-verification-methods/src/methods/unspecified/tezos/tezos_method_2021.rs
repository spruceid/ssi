use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use static_iref::iri;
use std::{collections::BTreeMap, hash::Hash};

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, TypedVerificationMethod, VerificationError, VerificationMethod,
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
/// a thezos key (so without multicodec, contrarily to the specification).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
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
                    Ok(Self::Jwk(Box::new(value.parse().map_err(|_| {
                        InvalidVerificationMethod::invalid_property("blockchainAccountId")
                    })?)))
                }
                Some(_) => Err(InvalidVerificationMethod::invalid_property(
                    "blockchainAccountId",
                )),
                None => Err(InvalidVerificationMethod::missing_property("publicKeyJwk")),
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
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
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
