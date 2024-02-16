use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::{protocol::Base58Btc, MessageSigner};
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{SignatureError, SolanaMethod2021, VerificationError};
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, suites::sha256_hash};

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
    pub const NAME: &'static str = "SolanaSignature2021";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#SolanaSignature2021");
}

impl_rdf_input_urdna2015!(SolanaSignature2021);

impl CryptographicSuite for SolanaSignature2021 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = SolanaMethod2021;

    type Signature = Signature;

    type SignatureProtocol = Base58Btc;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

    type Options = ();

    fn name(&self) -> &str {
        Self::NAME
    }

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
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    async fn sign(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        _method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        _bytes: &Self::Hashed,
        _signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as Referencable>::Reference<'_>,
    ) -> Result<ssi_claims_core::ProofValidity, VerificationError> {
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
        .is_ok()
        .into())
    }
}

// pub fn wallet_sign(message: &[u8], key: &JWK) -> Result<Vec<u8>, MessageSignatureError> {
//     let tx = LocalSolanaTransaction::with_message(message);
//     let bytes = tx.to_bytes();
//     let signature = ssi_jws::sign_bytes(ssi_jwk::Algorithm::EdDSA, &bytes, key)
//         .map_err(MessageSignatureError::signature_failed)?;
//     Ok(Base58Btc::encode_signature(&signature))
// }

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

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base58Btc encoded signature.
    pub proof_value: &'a str,
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
