use hex::FromHexError;
use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;
use std::hash::Hash;

use crate::{
    covariance_rule, ExpectedType, Referencable, SignatureError, TypedVerificationMethod,
    VerificationError, VerificationMethod,
};

pub const ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE: &str = "EcdsaSecp256k1RecoveryMethod2020";

/// EcdsaSecp256k1RecoveryMethod2020 verification method.
///
/// See: <https://w3c-ccg.github.io/security-vocab/#EcdsaSecp256k1RecoveryMethod2020>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(tag = "type", rename = "EcdsaSecp256k1RecoveryMethod2020")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:EcdsaSecp256k1RecoveryMethod2020")]
pub struct EcdsaSecp256k1RecoveryMethod2020 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Key controller.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public key.
    #[serde(flatten)]
    #[ld(flatten)]
    pub public_key: PublicKey,
}

impl Referencable for EcdsaSecp256k1RecoveryMethod2020 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for EcdsaSecp256k1RecoveryMethod2020 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for EcdsaSecp256k1RecoveryMethod2020 {
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
}

impl EcdsaSecp256k1RecoveryMethod2020 {
    pub fn sign(&self, data: &[u8], secret_key: &JWK) -> Result<CompactJWSString, SignatureError> {
        let algorithm = secret_key.algorithm.unwrap_or(ssi_jwk::Algorithm::ES256KR);
        if algorithm != ssi_jwk::Algorithm::ES256KR {
            return Err(SignatureError::InvalidSecretKey);
        }

        let header = ssi_jws::Header::new_unencoded(algorithm, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = ssi_jws::sign_bytes(algorithm, &signing_bytes, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)?;
        Ok(CompactJWSString::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn verify_bytes(&self, data: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
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
        Ok(ssi_jws::verify_bytes(ssi_jwk::Algorithm::ES256KR, data, &key, signature).is_ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "publicKeyHex")]
    #[ld("sec:publicKeyHex")]
    Hex(String),

    #[serde(rename = "ethereumAddress")]
    #[ld("sec:ethereumAddress")]
    EthereumAddress(ssi_security::EthereumAddressBuf),

    #[serde(rename = "blockchainAccountId")]
    #[ld("sec:blockchainAccoundId")]
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
                    return Err(InvalidPublicKey::InvalidParams);
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
}
