//! Tezos crypto suites.

pub mod ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021;
pub mod p256_blake2b_digest_size20_base58_check_encoded_signature_2021;
mod tezos_jcs_signature_2021;
pub mod tezos_signature_2021;

pub use ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
use linked_data::LinkedData;
pub use p256_blake2b_digest_size20_base58_check_encoded_signature_2021::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
use ssi_jwk::JWK;
use ssi_verification_methods::{covariance_rule, Referencable};
pub use tezos_jcs_signature_2021::TezosJcsSignature2021;
pub use tezos_signature_2021::TezosSignature2021;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, LinkedData)]
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

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            public_key_jwk: &self.public_key_jwk,
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy, serde::Serialize, LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct OptionsRef<'a> {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: &'a JWK,
}
