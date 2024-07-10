use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{MessageSignatureError, ProofValidationError};
use ssi_jwk::JWK;
use ssi_verification_methods_core::VerificationMethodSet;
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
};

// pub const BLOCKCHAIN_VERIFICATION_METHOD_2021_IRI: &Iri =
//     iri!("https://w3id.org/security#BlockchainVerificationMethod2021");

pub const BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE: &str = "BlockchainVerificationMethod2021";

/// BlockchainVerificationMethod2021.
///
/// See: <https://w3id.org/security#BlockchainVerificationMethod2021>.
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
#[serde(tag = "type", rename = "BlockchainVerificationMethod2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:BlockchainVerificationMethod2021")]
pub struct BlockchainVerificationMethod2021 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Blockchain accound ID.
    #[serde(rename = "blockchainAccountId")]
    #[ld("sec:blockchainAccountId")]
    pub blockchain_account_id: ssi_caips::caip10::BlockchainAccountId,
}

impl BlockchainVerificationMethod2021 {
    pub const NAME: &'static str = BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE;
    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#BlockchainVerificationMethod2021");

    pub fn verify_bytes(
        &self,
        public_key_jwk: Option<&JWK>,
        message: &[u8],
        algorithm: ssi_jwk::Algorithm,
        signature: &[u8],
    ) -> Result<bool, ProofValidationError> {
        match public_key_jwk {
            Some(jwk) => match self.blockchain_account_id.verify(jwk) {
                Ok(()) => Ok(ssi_jws::verify_bytes(algorithm, message, jwk, signature).is_ok()),
                Err(_) => Ok(false),
            },
            None => Err(ProofValidationError::MissingPublicKey),
        }
    }

    pub fn sign_bytes(
        &self,
        key: &JWK,
        algorithm: ssi_jwk::Algorithm,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm, bytes, key).map_err(MessageSignatureError::signature_failed)
    }
}

impl VerificationMethod for BlockchainVerificationMethod2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for BlockchainVerificationMethod2021 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for BlockchainVerificationMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE
    }

    fn type_(&self) -> &str {
        BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for BlockchainVerificationMethod2021 {
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
