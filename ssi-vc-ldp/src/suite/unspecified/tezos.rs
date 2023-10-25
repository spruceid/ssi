//! Tezos crypto suites.

pub mod ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021;
pub mod p256_blake2b_digest_size20_base58_check_encoded_signature_2021;
mod tezos_jcs_signature_2021;
pub mod tezos_signature_2021;

pub use ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
pub use p256_blake2b_digest_size20_base58_check_encoded_signature_2021::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
use ssi_jwk::JWK;
use ssi_verification_methods::{covariance_rule, Referencable};
pub use tezos_jcs_signature_2021::TezosJcsSignature2021;
pub use tezos_signature_2021::TezosSignature2021;

use crate::suite::CryptographicSuiteOptions;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct Options {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: Box<JWK>,
}

impl Options {
    pub fn new(public_key_jwk: JWK) -> Self {
        Self {
            public_key_jwk: Box::new(public_key_jwk),
        }
    }
}

impl<T> CryptographicSuiteOptions<T>for Options {}

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            public_key_jwk: &self.public_key_jwk,
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy, serde::Serialize, linked_data::Serialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct OptionsRef<'a> {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: &'a JWK,
}

pub enum Blake2bAlgorithm {
    EdBlake2b,
    ESBlake2bK,
    ESBlake2b
}

impl From<Blake2bAlgorithm> for ssi_jwk::Algorithm {
    fn from(value: Blake2bAlgorithm) -> Self {
        match value {
            Blake2bAlgorithm::EdBlake2b => Self::EdBlake2b,
            Blake2bAlgorithm::ESBlake2bK => Self::ESBlake2bK,
            Blake2bAlgorithm::ESBlake2b => Self::ESBlake2b
        }
    }
}

impl TryFrom<ssi_jwk::Algorithm> for Blake2bAlgorithm {
    type Error = ssi_jwk::algorithm::UnsupportedAlgorithm;
    
    fn try_from(value: ssi_jwk::Algorithm) -> Result<Self, Self::Error> {
        match value {
            ssi_jwk::Algorithm::EdBlake2b => Ok(Self::EdBlake2b),
            ssi_jwk::Algorithm::ESBlake2bK => Ok(Self::ESBlake2bK),
            ssi_jwk::Algorithm::ESBlake2b => Ok(Self::ESBlake2b),
            a => Err(ssi_jwk::algorithm::UnsupportedAlgorithm(a))
        }
    }
}