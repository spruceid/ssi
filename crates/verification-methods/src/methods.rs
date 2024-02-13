mod w3c;
use std::borrow::Cow;

use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_verification_methods_core::SigningMethod;
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

ssi_verification_methods_core::verification_method_union! {
    pub enum AnyMethod, AnyMethodRef, AnyMethodType {
        /// Deprecated verification method for the `RsaSignature2018` suite.
        RsaVerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2018` suite.
        Ed25519VerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2020` suite.
        Ed25519VerificationKey2020,

        EcdsaSecp256k1VerificationKey2019,

        EcdsaSecp256k1RecoveryMethod2020,

        EcdsaSecp256r1VerificationKey2019,

        /// `JsonWebKey2020`.
        JsonWebKey2020,

        /// `Multikey`.
        Multikey,

        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

        P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

        TezosMethod2021,

        AleoMethod2021,

        BlockchainVerificationMethod2021,

        Eip712Method2021,

        SolanaMethod2021
    }
}

impl AnyMethod {
    /// Returns the public key of the verification method as a JWK.
    ///
    /// Some methods don't have any the public key embedded.
    pub fn public_key_jwk(&self) -> Option<Cow<JWK>> {
        match self {
            Self::RsaVerificationKey2018(m) => Some(Cow::Borrowed(m.public_key_jwk())),
            Self::Ed25519VerificationKey2018(m) => Some(Cow::Owned(m.public_key_jwk())),
            Self::Ed25519VerificationKey2020(m) => Some(Cow::Owned(m.public_key_jwk())),
            Self::EcdsaSecp256k1VerificationKey2019(m) => Some(m.public_key_jwk()),
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => m.public_key_jwk(),
            Self::EcdsaSecp256r1VerificationKey2019(m) => Some(Cow::Owned(m.public_key_jwk())),
            Self::JsonWebKey2020(m) => Some(Cow::Borrowed(m.public_key_jwk())),
            Self::Multikey(m) => Some(Cow::Owned(m.public_key_jwk())),
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(_) => None,
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(_) => None,
            Self::TezosMethod2021(m) => m.public_key_jwk().map(Cow::Borrowed),
            Self::AleoMethod2021(_) => None,
            Self::BlockchainVerificationMethod2021(_) => None,
            Self::Eip712Method2021(_) => None,
            Self::SolanaMethod2021(m) => Some(Cow::Borrowed(m.public_key_jwk())),
        }
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
            AnyMethodRef::RsaVerificationKey2018(_) => todo!(),
            AnyMethodRef::Ed25519VerificationKey2018(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::Ed25519VerificationKey2020(_) => todo!(),
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
            AnyMethodRef::EcdsaSecp256r1VerificationKey2019(m) => match algorithm {
                ssi_jwk::Algorithm::ES256 => m.sign_bytes(secret, bytes),
                _ => Err(MessageSignatureError::UnsupportedAlgorithm(
                    algorithm.to_string(),
                )),
            },
            AnyMethodRef::JsonWebKey2020(_) => todo!(),
            AnyMethodRef::Multikey(_) => todo!(),
            AnyMethodRef::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021(m) => {
                m.sign_bytes(secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::TezosMethod2021(m) => m.sign_bytes(secret, algorithm.try_into()?, bytes),
            AnyMethodRef::AleoMethod2021(_) => todo!(),
            AnyMethodRef::BlockchainVerificationMethod2021(_) => todo!(),
            AnyMethodRef::Eip712Method2021(m) => {
                SigningMethod::sign_bytes(m, secret, algorithm.try_into()?, bytes)
            }
            AnyMethodRef::SolanaMethod2021(_) => todo!(),
        }
    }
}
