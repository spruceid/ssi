use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_caips::caip10::AleoBlockchainAccountId;
use ssi_claims_core::MessageSignatureError;
use ssi_jwk::JWK;
use static_iref::iri;
use std::hash::Hash;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod, VerificationMethodSet,
};

// pub const ALEO_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#AleoMethod2021");

pub const ALEO_METHOD_2021_TYPE: &str = "AleoMethod2021";

/// Aleo Method 2021.
///
/// Schnorr signature with [Edwards BLS12] curve
/// <https://developer.aleo.org/aleo/concepts/accounts>
///
/// The verification method object must have a `blockchainAccountId` property, identifying the
/// signer's Aleo
/// account address and network id for verification purposes. The chain id part of the account address
/// identifies an Aleo network as specified in the proposed [CAIP for Aleo Blockchain
/// Reference][caip-aleo-chain-ref]. Signatures use parameters defined per network. Currently only
/// network id "1" (CAIP-2 "aleo:1" / testnet1) is supported. The account
/// address format is documented in [Aleo
/// documentation](https://developer.aleo.org/aleo/concepts/accounts#account-address).
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
#[serde(tag = "type", rename = "AleoMethod2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:AleoMethod2021")]
pub struct AleoMethod2021 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Blockchain accound ID.
    #[serde(rename = "blockchainAccountId")]
    #[ld("sec:blockchainAccountId")]
    pub blockchain_account_id: AleoBlockchainAccountId,
}

impl AleoMethod2021 {
    pub const NAME: &'static str = ALEO_METHOD_2021_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#AleoMethod2021");

    pub fn sign_bytes(
        &self,
        key: &JWK, // FIXME: check key algorithm?
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jwk::aleo::sign(bytes, key).map_err(|_| MessageSignatureError::InvalidSecretKey)
    }

    pub fn verify_bytes(
        &self,
        _key: &JWK, // FIXME: check key algorithm?
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, MessageSignatureError> {
        match ssi_jwk::aleo::verify(
            bytes,
            &self.blockchain_account_id.account_address,
            signature,
        ) {
            Ok(()) => Ok(true),
            Err(ssi_jwk::aleo::AleoVerifyError::InvalidSignature) => Ok(false),
            Err(_) => Err(MessageSignatureError::InvalidSecretKey),
        }
    }
}

impl VerificationMethod for AleoMethod2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for AleoMethod2021 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for AleoMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(ALEO_METHOD_2021_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == ALEO_METHOD_2021_TYPE
    }

    fn type_(&self) -> &str {
        ALEO_METHOD_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for AleoMethod2021 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            blockchain_account_id: m
                .properties
                .get("blockchainAccountId")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("blockchainAccountId"))?
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("blockchainAccountId"))?
                .parse()
                .map_err(|_| InvalidVerificationMethod::invalid_property("blockchainAccountId"))?,
        })
    }
}
