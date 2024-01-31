//! Tezos crypto suites.

pub mod ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021;
pub mod p256_blake2b_digest_size20_base58_check_encoded_signature_2021;
pub mod tezos_jcs_signature_2021;
pub mod tezos_signature_2021;

use std::borrow::Cow;

pub use ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
pub use p256_blake2b_digest_size20_base58_check_encoded_signature_2021::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;
use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::{
    protocol::InvalidProtocolSignature, MessageSignatureError, MessageSigner, SignatureProtocol,
};
use ssi_jwk::{algorithm::AnyBlake2b, JWK};
use ssi_security::{Multibase, MultibaseBuf};
use ssi_verification_methods::{InvalidSignature, SignatureError, VerificationError};
pub use tezos_jcs_signature_2021::TezosJcsSignature2021;
pub use tezos_signature_2021::TezosSignature2021;

use crate::suite::{AnySignature, AnySignatureRef, CryptographicSuiteOptions};

const EDSIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];
const SPSIG_PREFIX: [u8; 5] = [13, 115, 101, 19, 63];
const P2SIG_PREFIX: [u8; 4] = [54, 240, 44, 52];

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
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

impl<T> CryptographicSuiteOptions<T> for Options {}

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

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct Signature {
    /// Base58check-encoded signature.
    ///
    /// Before encoding, the signature bytes are prefixed by a unique value
    /// identifying the cryptographic signature algorithm used.
    #[ld("sec:proofValue")]
    pub proof_value: String,
}

impl Signature {
    pub fn new(proof_value: String) -> Self {
        Self { proof_value }
    }

    pub async fn sign<'a, S: 'a + MessageSigner<AnyBlake2b, TezosWallet>>(
        public_key: Option<&JWK>,
        message: &'a [u8],
        signer: S,
    ) -> Result<Self, SignatureError> {
        match public_key {
            Some(jwk) => match jwk.algorithm.try_into() {
                Ok(algorithm) => {
                    let proof_value_bytes = signer.sign(algorithm, TezosWallet, message).await?;
                    match String::from_utf8(proof_value_bytes) {
                        Ok(proof_value) => Ok(Signature::new(proof_value)),
                        Err(_) => Err(SignatureError::InvalidSignature),
                    }
                }
                Err(e) => Err(MessageSignatureError::from(e).into()),
            },
            None => Err(SignatureError::MissingPublicKey),
        }
    }
}

impl Referencable for Signature {
    type Reference<'a> = SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        SignatureRef {
            proof_value: &self.proof_value,
        }
    }

    covariance_rule!();
}

impl From<Signature> for AnySignature {
    fn from(value: Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base58-encoded signature.
    pub proof_value: &'a str,
}

impl<'a> SignatureRef<'a> {
    pub fn decode(&self) -> Result<(AnyBlake2b, Vec<u8>), VerificationError> {
        TezosWallet::decode_signature(self.proof_value.as_bytes())
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

impl<'a> From<SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

/// Tezos Wallet protocol.
///
/// Used in combination with the `TezosSignature2021` and
/// `TezosJcsSignature2021` cryptographic suites. The signer (the Tezos Wallet)
/// must prefix the signature with a unique value identifying the signature
/// algorithm used, and encode the result in base58check.
pub struct TezosWallet;

impl TezosWallet {
    pub fn encode_signature(algorithm: AnyBlake2b, signature: &[u8]) -> Vec<u8> {
        let prefix: &[u8] = match algorithm {
            AnyBlake2b::EdBlake2b => &EDSIG_PREFIX,
            AnyBlake2b::ESBlake2bK => &SPSIG_PREFIX,
            AnyBlake2b::ESBlake2b => &P2SIG_PREFIX,
        };

        let mut sig_prefixed = Vec::with_capacity(prefix.len() + signature.len());
        sig_prefixed.extend_from_slice(prefix);
        sig_prefixed.extend_from_slice(signature);

        bs58::encode(sig_prefixed).with_check().into_vec()
    }

    pub fn decode_signature(
        encoded_signature: &[u8],
    ) -> Result<(AnyBlake2b, Vec<u8>), InvalidProtocolSignature> {
        let sig_prefixed = bs58::decode(encoded_signature)
            .with_check(None)
            .into_vec()
            .map_err(|_| InvalidProtocolSignature)?;

        if sig_prefixed.len() < 5 {
            return Err(InvalidProtocolSignature);
        }

        match &encoded_signature[0..5] {
            b"edsig" => Ok((AnyBlake2b::EdBlake2b, sig_prefixed[5..].to_vec())),
            b"spsig" => Ok((AnyBlake2b::ESBlake2bK, sig_prefixed[5..].to_vec())),
            b"p2sig" => Ok((AnyBlake2b::ESBlake2b, sig_prefixed[4..].to_vec())),
            _ => Err(InvalidProtocolSignature),
        }
    }
}

impl SignatureProtocol<AnyBlake2b> for TezosWallet {
    fn encode_signature(
        &self,
        algorithm: AnyBlake2b,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(Self::encode_signature(algorithm, &signature))
    }

    fn decode_signature<'s>(
        &self,
        encoded_signature: &'s [u8],
    ) -> Result<Cow<'s, [u8]>, InvalidProtocolSignature> {
        Self::decode_signature(encoded_signature).map(|(_, s)| Cow::Owned(s))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid Tezos multibase-encoded key")]
pub struct InvalidTezosMultibaseKey;

/// Encodes the given public JWK into a multibase Tezos-style base58 key.
pub fn encode_jwk_to_multibase(public_key: &JWK) -> Result<MultibaseBuf, ssi_jws::Error> {
    assert!(public_key.is_public());
    let tzkey = ssi_tzkey::jwk_to_tezos_key(&public_key.to_public())?;
    let mut result = String::with_capacity(1 + tzkey.len());
    result.push('z'); // base58 multibase prefix.
    result.push_str(&tzkey);
    Ok(MultibaseBuf::new(result))
}

/// Deocdes a public JWK from a multibase Tezos-style base58 key.
pub fn decode_jwk_from_multibase(key: &Multibase) -> Result<JWK, InvalidTezosMultibaseKey> {
    if key.as_str().starts_with('z') {
        ssi_tzkey::jwk_from_tezos_key(&key.as_str()[1..]).map_err(|_| InvalidTezosMultibaseKey)
    } else {
        Err(InvalidTezosMultibaseKey)
    }
}
