use hex::FromHexError;
use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use static_iref::iri;
use std::hash::Hash;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SigningMethod, TypedVerificationMethod, VerificationError, VerificationMethod,
};

pub const ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE: &str = "EcdsaSecp256k1RecoveryMethod2020";

/// EcdsaSecp256k1RecoveryMethod2020 verification method.
///
/// See: <https://w3c-ccg.github.io/security-vocab/#EcdsaSecp256k1RecoveryMethod2020>
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

    fn ref_id<'a>(r: Self::Reference<'a>) -> &'a Iri {
        r.id.as_iri()
    }

    fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a Iri> {
        Some(r.controller.as_iri())
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

    fn type_match(ty: &str) -> bool {
        ty == ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE
    }

    fn ref_type<'a>(_r: Self::Reference<'a>) -> &'a str {
        ECDSA_SECP_256K1_RECOVERY_METHOD_2020_TYPE
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("invalid secret key")]
    InvalidSecretKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestFunction {
    Sha256,
    Keccack,
}

impl DigestFunction {
    pub fn into_crypto_algorithm(self) -> ssi_jwk::Algorithm {
        match self {
            Self::Sha256 => ssi_jwk::Algorithm::ES256KR,
            Self::Keccack => ssi_jwk::Algorithm::ESKeccakKR,
        }
    }
}

impl EcdsaSecp256k1RecoveryMethod2020 {
    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#EcdsaSecp256k1RecoveryMethod2020");

    pub fn sign(
        &self,
        secret_key: &JWK,
        data: &[u8],
        digest_function: DigestFunction,
    ) -> Result<Vec<u8>, SignatureError> {
        let algorithm = digest_function.into_crypto_algorithm();
        let key_algorithm = secret_key.algorithm.unwrap_or(algorithm);
        if !algorithm.is_compatible_with(key_algorithm) {
            return Err(SignatureError::InvalidSecretKey);
        }

        ssi_jws::sign_bytes(algorithm, data, secret_key)
            .map_err(|_| SignatureError::InvalidSecretKey)
    }

    pub fn verify_bytes(
        &self,
        signing_bytes: &[u8],
        signature: &[u8],
        digest_function: DigestFunction,
    ) -> Result<bool, VerificationError> {
        // Recover the key used to sign the message.
        let algorithm = digest_function.into_crypto_algorithm();
        let key = ssi_jws::recover(algorithm, signing_bytes, signature)
            .map_err(|_| VerificationError::InvalidSignature)?;

        // Check the validity of the signing key.
        let matching_keys = self
            .public_key
            .matches(&key)
            .map_err(|_| VerificationError::InvalidProof)?;
        if !matching_keys {
            return Ok(false);
        }

        // Verify the signature.
        Ok(ssi_jws::verify_bytes(algorithm, signing_bytes, &key, signature).is_ok())
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

impl TryFrom<GenericVerificationMethod> for EcdsaSecp256k1RecoveryMethod2020 {
    type Error = InvalidVerificationMethod;

    fn try_from(mut m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        let public_key = match (
            m.properties.remove("publicKeyJwk"),
            m.properties.get("publicKeyHex"),
            m.properties.get("ethereumAddress"),
            m.properties.get("blockchainAccountId"),
        ) {
            (Some(k), None, None, None) => {
                PublicKey::Jwk(Box::new(serde_json::from_value(k).map_err(|_| {
                    InvalidVerificationMethod::invalid_property("publicKeyJwk")
                })?))
            }
            (None, Some(k), None, None) => PublicKey::Hex(
                k.as_str()
                    .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyHex"))?
                    .to_owned(),
            ),
            (None, None, Some(k), None) => PublicKey::EthereumAddress(
                k.as_str()
                    .ok_or_else(|| InvalidVerificationMethod::invalid_property("ethereumAddress"))?
                    .parse()
                    .map_err(|_| InvalidVerificationMethod::invalid_property("ethereumAddress"))?,
            ),
            (None, None, None, Some(k)) => PublicKey::BlockchainAccountId(
                k.as_str()
                    .ok_or_else(|| {
                        InvalidVerificationMethod::invalid_property("blockchainAccountId")
                    })?
                    .parse()
                    .map_err(|_| {
                        InvalidVerificationMethod::invalid_property("blockchainAccountId")
                    })?,
            ),
            (None, None, None, None) => {
                return Err(InvalidVerificationMethod::missing_property("publicKeyJwk"))
            }
            _ => return Err(InvalidVerificationMethod::AmbiguousPublicKey),
        };

        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key,
        })
    }
}

impl SigningMethod<JWK, ssi_jwk::algorithm::ES256KR> for EcdsaSecp256k1RecoveryMethod2020 {
    fn sign_bytes_ref(
        this: Self::Reference<'_>,
        secret: &JWK,
        _algorithm: ssi_jwk::algorithm::ES256KR,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        this.sign(secret, bytes, DigestFunction::Sha256)
            .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))
    }
}

impl SigningMethod<JWK, ssi_jwk::algorithm::ESKeccakKR> for EcdsaSecp256k1RecoveryMethod2020 {
    fn sign_bytes_ref(
        this: Self::Reference<'_>,
        secret: &JWK,
        _algorithm: ssi_jwk::algorithm::ESKeccakKR,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        this.sign(secret, bytes, DigestFunction::Keccack)
            .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))
    }
}
