mod w3c;
use std::borrow::Cow;

use ssi_claims_core::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_verification_methods_core::{
    GenericVerificationMethod, JwkVerificationMethod, MaybeJwkVerificationMethod, SigningMethod,
};
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

ssi_verification_methods_core::complete_verification_method_union! {
    pub enum AnyMethod, AnyMethodType, AnyMethodTypeRef {
        /// `Multikey`.
        Multikey,

        /// `JsonWebKey2020`.
        JsonWebKey2020,

        /// Deprecated verification method for the `RsaSignature2018` suite.
        #[cfg(feature = "rsa")]
        RsaVerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2018` suite.
        #[cfg(feature = "ed25519")]
        Ed25519VerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2020` suite.
        #[cfg(feature = "ed25519")]
        Ed25519VerificationKey2020,

        #[cfg(feature = "secp256k1")]
        EcdsaSecp256k1VerificationKey2019,

        #[cfg(feature = "secp256k1")]
        EcdsaSecp256k1RecoveryMethod2020,

        #[cfg(feature = "secp256r1")]
        EcdsaSecp256r1VerificationKey2019,

        #[cfg(all(feature = "tezos", feature = "ed25519"))]
        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

        #[cfg(all(feature = "tezos", feature = "secp256r1"))]
        P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

        #[cfg(feature = "tezos")]
        TezosMethod2021,

        #[cfg(feature = "aleo")]
        AleoMethod2021,

        BlockchainVerificationMethod2021,

        #[cfg(all(feature = "eip712", feature = "secp256k1"))]
        Eip712Method2021,

        #[cfg(feature = "solana")]
        SolanaMethod2021
    }
}

impl AnyMethod {
    /// Returns the public key of the verification method as a JWK.
    ///
    /// Some methods don't have any the public key embedded.
    pub fn public_key_jwk(&self) -> Option<Cow<JWK>> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaVerificationKey2018(m) => Some(Cow::Borrowed(m.public_key_jwk())),
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2018(m) => Some(Cow::Owned(m.public_key_jwk())),
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2020(m) => Some(Cow::Owned(m.public_key_jwk())),
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019(m) => Some(m.public_key_jwk()),
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => m.public_key_jwk(),
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1VerificationKey2019(m) => Some(Cow::Owned(m.public_key_jwk())),
            Self::JsonWebKey2020(m) => Some(Cow::Borrowed(m.public_key_jwk())),
            Self::Multikey(m) => m.public_key_jwk().map(Cow::Owned),
            #[cfg(all(feature = "tezos", feature = "ed25519"))]
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(_) => None,
            #[cfg(all(feature = "tezos", feature = "secp256r1"))]
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(_) => None,
            #[cfg(feature = "tezos")]
            Self::TezosMethod2021(m) => m.public_key_jwk().map(Cow::Borrowed),
            #[cfg(feature = "aleo")]
            Self::AleoMethod2021(_) => None,
            Self::BlockchainVerificationMethod2021(_) => None,
            #[cfg(all(feature = "eip712", feature = "secp256k1"))]
            Self::Eip712Method2021(_) => None,
            #[cfg(feature = "solana")]
            Self::SolanaMethod2021(m) => Some(Cow::Borrowed(m.public_key_jwk())),
            _ => None,
        }
    }
}

impl From<AnyMethod> for GenericVerificationMethod {
    fn from(value: AnyMethod) -> Self {
        // TODO: implement something better that a JSON roundtrip.
        let json = serde_json::to_value(value).unwrap();
        serde_json::from_value(json).unwrap()
    }
}

impl MaybeJwkVerificationMethod for AnyMethod {
    fn try_to_jwk(&self) -> Option<Cow<JWK>> {
        self.public_key_jwk()
    }
}

impl SigningMethod<JWK, ssi_crypto::Algorithm> for AnyMethod {
    fn sign_bytes(
        &self,
        secret: &JWK,
        algorithm: ssi_crypto::AlgorithmInstance,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaVerificationKey2018(m) => m.sign_bytes(bytes, secret),
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2018(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2020(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::EdDSA => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::ES256K => m.sign_bytes(
                    secret,
                    ecdsa_secp_256k1_verification_key_2019::DigestFunction::Sha256,
                    bytes,
                ),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::ES256KR => {
                    SigningMethod::<_, ssi_crypto::algorithm::ES256KR>::sign_bytes(
                        m,
                        secret,
                        ssi_crypto::algorithm::ES256KR,
                        bytes,
                    )
                }
                ssi_crypto::AlgorithmInstance::ESKeccakKR => {
                    SigningMethod::<_, ssi_crypto::algorithm::ESKeccakKR>::sign_bytes(
                        m,
                        secret,
                        ssi_crypto::algorithm::ESKeccakKR,
                        bytes,
                    )
                }
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1VerificationKey2019(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::ES256 => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            Self::JsonWebKey2020(m) => m.sign_bytes(secret, Some(algorithm.try_into()?), bytes),
            Self::Multikey(m) => {
                SigningMethod::<_, ssi_crypto::Algorithm>::sign_bytes(m, secret, algorithm, bytes)
            }
            #[cfg(all(feature = "tezos", feature = "ed25519"))]
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(all(feature = "tezos", feature = "secp256r1"))]
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "tezos")]
            Self::TezosMethod2021(m) => m.sign_bytes(secret, algorithm.try_into()?, bytes),
            #[cfg(feature = "aleo")]
            Self::AleoMethod2021(m) => {
                m.sign_bytes(secret, bytes) // FIXME: check key algorithm?
            }
            Self::BlockchainVerificationMethod2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(all(feature = "eip712", feature = "secp256k1"))]
            Self::Eip712Method2021(m) => {
                SigningMethod::sign_bytes(m, secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "solana")]
            Self::SolanaMethod2021(m) => {
                m.sign_bytes(secret, Some(algorithm.try_into()?), bytes) // FIXME: check algorithm?
            }
            m => Err(MessageSignatureError::UnsupportedVerificationMethod(
                m.type_().name().to_owned(),
            )),
        }
    }

    fn sign_bytes_multi(
        &self,
        secret: &JWK,
        algorithm: ssi_crypto::AlgorithmInstance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match self {
            Self::Multikey(m) => SigningMethod::<_, ssi_crypto::Algorithm>::sign_bytes_multi(
                m, secret, algorithm, messages,
            ),
            m => Err(MessageSignatureError::UnsupportedVerificationMethod(
                m.type_().name().to_owned(),
            )),
        }
    }
}

ssi_verification_methods_core::verification_method_union! {
    pub enum AnyJwkMethod, AnyJwkMethodType {
        /// `JsonWebKey2020`.
        JsonWebKey2020,

        /// Deprecated verification method for the `RsaSignature2018` suite.
        #[cfg(feature = "rsa")]
        RsaVerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2018` suite.
        #[cfg(feature = "ed25519")]
        Ed25519VerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2020` suite.
        #[cfg(feature = "ed25519")]
        Ed25519VerificationKey2020,

        #[cfg(feature = "secp256k1")]
        EcdsaSecp256k1VerificationKey2019,

        #[cfg(feature = "secp256r1")]
        EcdsaSecp256r1VerificationKey2019,

        #[cfg(feature = "solana")]
        SolanaMethod2021
    }
}

impl AnyJwkMethod {
    /// Returns the public key of the verification method as a JWK.
    ///
    /// Some methods don't have any the public key embedded.
    pub fn public_key_jwk(&self) -> Cow<JWK> {
        match self {
            Self::JsonWebKey2020(m) => Cow::Borrowed(m.public_key_jwk()),
            #[cfg(feature = "rsa")]
            Self::RsaVerificationKey2018(m) => Cow::Borrowed(m.public_key_jwk()),
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2018(m) => Cow::Owned(m.public_key_jwk()),
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2020(m) => Cow::Owned(m.public_key_jwk()),
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019(m) => m.public_key_jwk(),
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1VerificationKey2019(m) => Cow::Owned(m.public_key_jwk()),
            #[cfg(feature = "solana")]
            Self::SolanaMethod2021(m) => Cow::Borrowed(m.public_key_jwk()),
        }
    }
}

impl JwkVerificationMethod for AnyJwkMethod {
    fn to_jwk(&self) -> Cow<JWK> {
        self.public_key_jwk()
    }
}

impl SigningMethod<JWK, ssi_crypto::Algorithm> for AnyJwkMethod {
    fn sign_bytes(
        &self,
        secret: &JWK,
        algorithm: ssi_crypto::AlgorithmInstance,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaVerificationKey2018(m) => m.sign_bytes(bytes, secret),
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2018(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519VerificationKey2020(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::EdDSA => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::ES256K => m.sign_bytes(
                    secret,
                    ecdsa_secp_256k1_verification_key_2019::DigestFunction::Sha256,
                    bytes,
                ),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1VerificationKey2019(m) => match algorithm {
                ssi_crypto::AlgorithmInstance::ES256 => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.algorithm().to_string(),
                )),
            },
            Self::JsonWebKey2020(m) => m.sign_bytes(secret, Some(algorithm.try_into()?), bytes),
            #[cfg(feature = "solana")]
            Self::SolanaMethod2021(m) => {
                m.sign_bytes(secret, Some(algorithm.try_into()?), bytes) // FIXME: check algorithm?
            }
        }
    }
}
