use ssi_crypto::{protocol::Base58Btc, MessageSignatureError, MessageSigner};
use ssi_jwk::JWK;
use ssi_verification_methods::{
    covariance_rule, InvalidSignature, Referencable, SignatureError, SolanaMethod2021,
    VerificationError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, AnySignature, AnySignatureRef, HashError},
    CryptographicSuite, ProofConfigurationRef,
};

/// Solana Signature 2021
///
/// Linked data signature suite using Solana.
///
/// # Transformation algorithm
///
/// This suite accepts linked data documents transformed into a canonical
/// RDF graph using the [URDNA2015][1] algorithm.
///
/// [1]: <https://w3id.org/security#URDNA2015>
///
/// # Hashing algorithm
///
/// The SHA-256 algorithm is used to hash the input canonical RDF graph and the
/// proof configuration graph, also in canonical form. Both hashes are then
/// concatenated into a single 64-bytes message, ready to be signed.
///
/// # Verification method
///
/// The following verification methods my be used to sign/verify a credential
/// with this suite:
/// - [`SolanaMethod2021`]
///
/// # Signature protocol
///
/// The [`SolanaWallet`] protocol is used.
pub struct SolanaSignature2021;

impl SolanaSignature2021 {
    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#SolanaSignature2021");
}

impl_rdf_input_urdna2015!(SolanaSignature2021);

impl CryptographicSuite for SolanaSignature2021 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = SolanaMethod2021;

    type Signature = Signature;

    type SignatureProtocol = Base58Btc;

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    /// Base58Btc encoded signature.
    pub proof_value: String,
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
        AnySignature {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl TryFrom<AnySignature> for Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base58Btc encoded signature.
    pub proof_value: &'a str,
}

impl<'a> From<SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: SignatureRef<'a>) -> Self {
        AnySignatureRef {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

pub struct SignatureAlgorithm;

impl SignatureAlgorithm {
    pub fn wallet_sign(message: &[u8], key: &JWK) -> Result<Vec<u8>, MessageSignatureError> {
        let tx = LocalSolanaTransaction::with_message(&message);
        let bytes = tx.to_bytes();
        let signature = ssi_jws::sign_bytes(ssi_jwk::Algorithm::EdDSA, &bytes, key)
            .map_err(MessageSignatureError::signature_failed)?;
        Ok(Base58Btc::encode_signature(&signature))
    }
}

pub struct LocalSolanaTransaction {
    bytes: Vec<u8>,
}

impl LocalSolanaTransaction {
    pub fn with_message(bytes: &[u8]) -> Self {
        // TODO
        Self {
            bytes: bytes.into(),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO
        self.bytes.clone()
    }
}

impl ssi_verification_methods::SignatureAlgorithm<SolanaMethod2021> for SignatureAlgorithm {
    type Options = ();

    type Signature = Signature;

    type Protocol = Base58Btc;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        _method: <SolanaMethod2021 as Referencable>::Reference<'_>,
        _bytes: &[u8],
        _signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        _options: (),
        signature: SignatureRef,
        method: &SolanaMethod2021,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let tx = LocalSolanaTransaction::with_message(bytes);
        let signing_bytes = tx.to_bytes();

        let signature_bytes = Base58Btc::decode_signature(signature.proof_value.as_bytes())
            .map_err(|_| VerificationError::InvalidSignature)?;
        Ok(ssi_jws::verify_bytes(
            ssi_jwk::Algorithm::EdDSA,
            &signing_bytes,
            &method.public_key,
            &signature_bytes,
        )
        .is_ok())
    }
}
