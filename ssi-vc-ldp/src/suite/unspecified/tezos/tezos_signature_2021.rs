use std::future;
use ssi_crypto::MessageSigner;
use ssi_jwk::JWK;
use ssi_rdf::IntoNQuads;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{
    covariance_rule, InvalidSignature, Referencable, SignatureError, TezosMethod2021,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{AnySignature, AnySignatureRef, HashError},
    CryptographicSuite, ProofConfigurationRef,
};

use super::Blake2bAlgorithm;

/// Tezos signature suite based on URDNA2015.
///
/// # Transformation algorithm
///
/// The input credential RDF graph is normalized into a list of RDF quads using
/// the URDNA2015 canonicalization algorithm.
///
/// # Hashing algorithm
///
/// The proof configuration RDF graph is normalized into into a list of RDF
/// quads using the URDNA2015 canonicalization algorithm. A message is formed
/// by concatenating the `Tezos Signed Message: ` (ending with a space), the
/// credential quads and the configuration quads using the 0xa byte (line feed).
///
/// The output is a bytes string composed of the byte 0x5, followed by the byte
/// 0x1, followed by the 4 bytes encoding the message lenght in big endian,
/// followd by the message.
///
/// [1]: <https://tools.ietf.org/html/rfc8785>
///
/// # Verification method
///
/// The [`TezosMethod2021`] verification method is used.
pub struct TezosSignature2021;

impl TezosSignature2021 {
    pub const IRI: &iref::Iri = iri!("https://w3id.org/security#TezosSignature2021");
}

impl_rdf_input_urdna2015!(TezosSignature2021);

impl CryptographicSuite for TezosSignature2021 {
    type Transformed = String;
    type Hashed = Vec<u8>;

    type VerificationMethod = TezosMethod2021;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = Blake2bAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads(self).into_nquads();
        let message = format!("\n{data}\n{proof_quads}");
        match ssi_tzkey::encode_tezos_signed_message(&message) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct Signature {
    /// Base58-encoded signature.
    #[ld("sec:proofValue")]
    pub proof_value: String,

    /// Signing key.
    #[ld(flatten)]
    pub public_key: Option<PublicKey>,
}

impl Referencable for Signature {
    type Reference<'a> = SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        SignatureRef {
            proof_value: &self.proof_value,
            public_key: self.public_key.as_ref().map(|k| match k {
                PublicKey::Jwk(jwk) => PublicKeyRef::Jwk(jwk),
                PublicKey::Multibase(m) => PublicKeyRef::Multibase(m),
            }),
        }
    }

    covariance_rule!();
}

impl From<Signature> for AnySignature {
    fn from(value: Signature) -> Self {
        let mut public_key_jwk = None;
        let mut public_key_multibase = None;

        match value.public_key {
            Some(PublicKey::Jwk(k)) => public_key_jwk = Some(k),
            Some(PublicKey::Multibase(k)) => public_key_multibase = Some(k),
            None => (),
        }

        Self {
            proof_value: Some(value.proof_value),
            public_key_jwk,
            public_key_multibase,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base58-encoded signature.
    pub proof_value: &'a str,

    /// Signing key.
    pub public_key: Option<PublicKeyRef<'a>>,
}

impl<'a> From<SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: SignatureRef<'a>) -> Self {
        let mut public_key_jwk = None;
        let mut public_key_multibase = None;

        match value.public_key {
            Some(PublicKeyRef::Jwk(k)) => public_key_jwk = Some(k),
            Some(PublicKeyRef::Multibase(k)) => public_key_multibase = Some(k),
            None => (),
        }

        Self {
            proof_value: Some(value.proof_value),
            public_key_jwk,
            public_key_multibase,
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        let public_key = match (value.public_key_jwk, value.public_key_multibase) {
            (Some(k), None) => Some(PublicKeyRef::Jwk(k)),
            (None, Some(k)) => Some(PublicKeyRef::Multibase(k)),
            (Some(_), Some(_)) => return Err(InvalidSignature::AmbiguousPublicKey),
            (None, None) => None,
        };

        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
            public_key,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub enum PublicKey {
    #[ld("sec:publicKeyJwk")]
    Jwk(Box<JWK>),

    #[ld("sec:publicKeyMultibase")]
    Multibase(String),
}

#[derive(Debug, Clone, Copy)]
pub enum PublicKeyRef<'a> {
    Jwk(&'a JWK),
    Multibase(&'a str),
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<TezosMethod2021> for SignatureAlgorithm {
    type Options = ();

    type Signature = Signature;

    type Protocol = ();

    type MessageSignatureAlgorithm = Blake2bAlgorithm;

    type Sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: (),
        method: &TezosMethod2021,
        bytes: &[u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        options: (),
        signature: SignatureRef,
        method: &TezosMethod2021,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
