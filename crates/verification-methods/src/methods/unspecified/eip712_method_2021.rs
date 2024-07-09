use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_caips::caip10::BlockchainAccountIdVerifyError;
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_jwk::JWK;
use ssi_verification_methods_core::VerificationMethodSet;
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, SigningMethod,
    TypedVerificationMethod, VerificationMethod,
};

// mod context;
// pub use context::*;

// pub const EIP712_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#Eip712Method2021");

pub const EIP712_METHOD_2021_TYPE: &str = "Eip712Method2021";

/// `Eip712Method2021`.
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
#[serde(tag = "type", rename = "Eip712Method2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:Eip712Method2021")]
pub struct Eip712Method2021 {
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

impl Eip712Method2021 {
    pub const NAME: &'static str = EIP712_METHOD_2021_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#Eip712Method2021");

    pub fn sign_bytes(
        &self,
        secret_key: &JWK,
        data: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        use sha3::Digest;
        use ssi_jwk::Params;
        let ec_params = match &secret_key.params {
            Params::EC(ec) => ec,
            _ => return Err(MessageSignatureError::InvalidSecretKey),
        };

        let secret_key = k256::SecretKey::try_from(ec_params)
            .map_err(|_| MessageSignatureError::InvalidSecretKey)?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let (sig, rec_id) = signing_key
            .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(data))
            .map_err(MessageSignatureError::signature_failed)?;

        // let sig: k256::ecdsa::recoverable::Signature = signing_key
        //     .try_sign(data)
        //     .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))?;

        let mut result = sig.to_bytes().to_vec();
        result.push(rec_id.to_byte());

        Ok(result)
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        use sha3::Digest;
        if signature_bytes.len() != 65 {
            return Err(ProofValidationError::InvalidSignature);
        }

        // Interpret the signature.
        let signature = k256::ecdsa::Signature::try_from(&signature_bytes[..64])
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        // Recover the signing key.
        let rec_id = k256::ecdsa::RecoveryId::try_from(signature_bytes[64])
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        let recovered_key: k256::ecdsa::VerifyingKey =
            k256::ecdsa::VerifyingKey::recover_from_digest(
                sha3::Keccak256::new_with_prefix(data),
                &signature,
                rec_id,
            )
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        // Check the signing key.
        let jwk = JWK {
            params: ssi_jwk::Params::EC(ssi_jwk::ECParams::from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes()).unwrap(),
            )),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };

        match self.blockchain_account_id.verify(&jwk) {
            Ok(()) => Ok(Ok(())),
            Err(BlockchainAccountIdVerifyError::KeyMismatch(_, _)) => {
                Ok(Err(InvalidProof::KeyMismatch))
            }
            Err(_) => Err(ProofValidationError::InvalidKey),
        }
    }
}

impl VerificationMethod for Eip712Method2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for Eip712Method2021 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for Eip712Method2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(EIP712_METHOD_2021_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == EIP712_METHOD_2021_TYPE
    }

    fn type_(&self) -> &str {
        EIP712_METHOD_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for Eip712Method2021 {
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

impl SigningMethod<JWK, ssi_crypto::algorithm::ESKeccakKR> for Eip712Method2021 {
    fn sign_bytes(
        &self,
        key: &JWK,
        _algorithm: ssi_crypto::algorithm::ESKeccakKR,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        self.sign_bytes(key, bytes)
    }
}
