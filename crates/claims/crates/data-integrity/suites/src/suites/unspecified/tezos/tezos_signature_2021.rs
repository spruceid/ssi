use crate::{try_from_type, TezosWallet};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_crypto::algorithm::AnyBlake2b;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalClaimsAndConfiguration, CanonicalizeClaimsAndConfiguration},
    suite::{
        standard::{
            HashingAlgorithm, HashingError, SignatureAlgorithm, SignatureAndVerificationAlgorithm,
            VerificationAlgorithm,
        },
        AddProofContext,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_jwk::JWK;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{protocol::WithProtocol, MessageSigner, TezosMethod2021};
use static_iref::iri;

use super::{Signature, TezosVmV1Context};

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
#[derive(Debug, Default, Clone, Copy)]
pub struct TezosSignature2021;

impl TezosSignature2021 {
    pub const NAME: &'static str = "TezosSignature2021";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#TezosSignature2021");
}

impl StandardCryptographicSuite for TezosSignature2021 {
    type Configuration = AddProofContext<TezosVmV1Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = EncodeTezosMessage;

    type VerificationMethod = TezosMethod2021;

    type SignatureAlgorithm = TezosSignatureAlgorithm;

    type ProofOptions = Options;

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(TezosSignature2021);

pub struct EncodeTezosMessage;

impl HashingAlgorithm<TezosSignature2021> for EncodeTezosMessage {
    type Output = Vec<u8>;

    fn hash(
        input: CanonicalClaimsAndConfiguration,
        _proof_configuration: ProofConfigurationRef<TezosSignature2021>,
        _verification_method: &TezosMethod2021,
    ) -> Result<Vec<u8>, HashingError> {
        let mut message = '\n'.to_string();

        for line in input.configuration {
            message.push_str(&line);
        }

        message.push('\n');

        for line in input.claims {
            message.push_str(&line);
        }

        match ssi_tzkey::encode_tezos_signed_message(&message) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashingError::TooLong),
        }
    }
}

pub struct TezosSignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for TezosSignatureAlgorithm {
    type Signature = Signature;
}

impl<T> SignatureAlgorithm<TezosSignature2021, T> for TezosSignatureAlgorithm
where
    T: MessageSigner<WithProtocol<AnyBlake2b, TezosWallet>>,
{
    async fn sign(
        verification_method: &<TezosSignature2021 as CryptographicSuite>::VerificationMethod,
        signer: T,
        prepared_claims: Vec<u8>,
        proof_configuration: ProofConfigurationRef<'_, TezosSignature2021>,
    ) -> Result<Self::Signature, SignatureError> {
        // AnyBlake2b
        Signature::sign(
            verification_method
                .public_key
                .as_jwk()
                .or(proof_configuration.options.public_key_jwk.as_deref()),
            &prepared_claims,
            signer,
        )
        .await
    }
}

impl VerificationAlgorithm<TezosSignature2021> for TezosSignatureAlgorithm {
    fn verify(
        method: &TezosMethod2021,
        prepared_claims: Vec<u8>,
        proof: ProofRef<TezosSignature2021>,
    ) -> Result<ProofValidity, ProofValidationError> {
        // AnyBlake2b
        let (algorithm, signature_bytes) = proof.signature.decode()?;
        method
            .verify_bytes(
                proof.options.public_key_jwk.as_deref(),
                &prepared_claims,
                algorithm,
                &signature_bytes,
            )
            .map(Into::into)
    }
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
pub struct Options {
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: Option<Box<JWK>>,
}

impl Options {
    pub fn new(public_key_jwk: Option<JWK>) -> Self {
        Self {
            public_key_jwk: public_key_jwk.map(Box::new),
        }
    }
}
