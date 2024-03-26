mod w3c;
use std::borrow::Cow;

use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_verification_methods_core::{
    JwkVerificationMethod, MaybeJwkVerificationMethod, SigningMethod,
};
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

ssi_verification_methods_core::verification_method_union! {
    pub enum AnyMethod, AnyMethodRef, AnyMethodType {
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

        /// `JsonWebKey2020`.
        JsonWebKey2020,

        /// `Multikey`.
        #[cfg(feature = "ed25519")]
        Multikey,

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
            #[cfg(feature = "ed25519")]
            Self::Multikey(m) => Some(Cow::Owned(m.public_key_jwk())),
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
        }
    }
}

impl<'a> AnyMethodRef<'a> {
    /// Returns the public key of the verification method as a JWK.
    ///
    /// Some methods don't have any the public key embedded.
    pub fn public_key_jwk(&self) -> Option<Cow<'a, JWK>> {
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
            #[cfg(feature = "ed25519")]
            Self::Multikey(m) => Some(Cow::Owned(m.public_key_jwk())),
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
        }
    }
}

impl MaybeJwkVerificationMethod for AnyMethod {
    fn try_to_jwk(&self) -> Option<Cow<JWK>> {
        self.public_key_jwk()
    }

    fn try_ref_to_jwk(r: Self::Reference<'_>) -> Option<Cow<'_, JWK>> {
        r.public_key_jwk()
    }
}

impl SigningMethod<JWK, ssi_jwk::Algorithm> for AnyMethod {
    fn sign_bytes_ref(
        this: AnyMethodRef,
        secret: &JWK,
        algorithm: ssi_jwk::Algorithm,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match this {
            #[cfg(feature = "rsa")]
            AnyMethodRef::RsaVerificationKey2018(m) => m.sign_bytes(bytes, secret),
            #[cfg(feature = "ed25519")]
            AnyMethodRef::Ed25519VerificationKey2018(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "ed25519")]
            AnyMethodRef::Ed25519VerificationKey2020(m) => match algorithm {
                ssi_jwk::Algorithm::EdDSA => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(feature = "secp256k1")]
            AnyMethodRef::EcdsaSecp256k1VerificationKey2019(m) => match algorithm {
                ssi_jwk::Algorithm::ES256K => m.sign_bytes(
                    secret,
                    ecdsa_secp_256k1_verification_key_2019::DigestFunction::Sha256,
                    bytes,
                ),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(feature = "secp256k1")]
            AnyMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => match algorithm {
                ssi_jwk::Algorithm::ES256KR => {
                    m.sign_bytes(secret, ssi_jwk::algorithm::ES256KR, bytes)
                }
                ssi_jwk::Algorithm::ESKeccakKR => {
                    m.sign_bytes(secret, ssi_jwk::algorithm::ESKeccakKR, bytes)
                }
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(feature = "secp256r1")]
            AnyMethodRef::EcdsaSecp256r1VerificationKey2019(m) => match algorithm {
                ssi_jwk::Algorithm::ES256 => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            AnyMethodRef::JsonWebKey2020(m) => m.sign_bytes(secret, Some(algorithm), bytes),
            #[cfg(feature = "ed25519")]
            AnyMethodRef::Multikey(m) => match algorithm {
                ssi_jwk::Algorithm::EdDSA => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(all(feature = "tezos", feature = "ed25519"))]
            AnyMethodRef::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(all(feature = "tezos", feature = "secp256r1"))]
            AnyMethodRef::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "tezos")]
            AnyMethodRef::TezosMethod2021(m) => m.sign_bytes(secret, algorithm.try_into()?, bytes),
            #[cfg(feature = "aleo")]
            AnyMethodRef::AleoMethod2021(m) => {
                m.sign_bytes(secret, bytes) // FIXME: check key algorithm?
            }
            AnyMethodRef::BlockchainVerificationMethod2021(m) => {
                m.sign_bytes(secret, algorithm, bytes)
            }
            #[cfg(all(feature = "eip712", feature = "secp256k1"))]
            AnyMethodRef::Eip712Method2021(m) => {
                SigningMethod::sign_bytes(m, secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "solana")]
            AnyMethodRef::SolanaMethod2021(m) => {
                m.sign_bytes(secret, Some(algorithm), bytes) // FIXME: check algorithm?
            }
        }
    }
}

ssi_verification_methods_core::verification_method_union! {
    pub enum AnyJwkMethod, AnyJwkMethodRef, AnyJwkMethodType {
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

        /// `JsonWebKey2020`.
        JsonWebKey2020,

        /// `Multikey`.
        #[cfg(feature = "ed25519")]
        Multikey,

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
            Self::JsonWebKey2020(m) => Cow::Borrowed(m.public_key_jwk()),
            #[cfg(feature = "ed25519")]
            Self::Multikey(m) => Cow::Owned(m.public_key_jwk()),
            #[cfg(feature = "solana")]
            Self::SolanaMethod2021(m) => Cow::Borrowed(m.public_key_jwk()),
        }
    }
}

impl<'a> AnyJwkMethodRef<'a> {
    pub fn public_key_jwk(&self) -> Cow<'a, JWK> {
        match self {
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
            Self::JsonWebKey2020(m) => Cow::Borrowed(m.public_key_jwk()),
            #[cfg(feature = "ed25519")]
            Self::Multikey(m) => Cow::Owned(m.public_key_jwk()),
            #[cfg(feature = "solana")]
            Self::SolanaMethod2021(m) => Cow::Borrowed(m.public_key_jwk()),
        }
    }
}

impl JwkVerificationMethod for AnyJwkMethod {
    fn to_jwk(&self) -> Cow<JWK> {
        self.public_key_jwk()
    }

    fn ref_to_jwk(r: Self::Reference<'_>) -> Cow<'_, JWK> {
        r.public_key_jwk()
    }
}

impl SigningMethod<JWK, ssi_jwk::Algorithm> for AnyJwkMethod {
    fn sign_bytes_ref(
        this: AnyJwkMethodRef,
        secret: &JWK,
        algorithm: ssi_jwk::Algorithm,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match this {
            #[cfg(feature = "rsa")]
            AnyJwkMethodRef::RsaVerificationKey2018(m) => m.sign_bytes(bytes, secret),
            #[cfg(feature = "ed25519")]
            AnyJwkMethodRef::Ed25519VerificationKey2018(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            #[cfg(feature = "ed25519")]
            AnyJwkMethodRef::Ed25519VerificationKey2020(m) => match algorithm {
                ssi_jwk::Algorithm::EdDSA => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(feature = "secp256k1")]
            AnyJwkMethodRef::EcdsaSecp256k1VerificationKey2019(m) => match algorithm {
                ssi_jwk::Algorithm::ES256K => m.sign_bytes(
                    secret,
                    ecdsa_secp_256k1_verification_key_2019::DigestFunction::Sha256,
                    bytes,
                ),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(feature = "secp256r1")]
            AnyJwkMethodRef::EcdsaSecp256r1VerificationKey2019(m) => match algorithm {
                ssi_jwk::Algorithm::ES256 => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            AnyJwkMethodRef::JsonWebKey2020(m) => m.sign_bytes(secret, Some(algorithm), bytes),
            #[cfg(feature = "ed25519")]
            AnyJwkMethodRef::Multikey(m) => match algorithm {
                ssi_jwk::Algorithm::EdDSA => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            #[cfg(feature = "solana")]
            AnyJwkMethodRef::SolanaMethod2021(m) => {
                m.sign_bytes(secret, Some(algorithm), bytes) // FIXME: check algorithm?
            }
        }
    }
}
