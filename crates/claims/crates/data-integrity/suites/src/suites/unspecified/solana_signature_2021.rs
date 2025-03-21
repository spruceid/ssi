use k256::sha2::Sha256;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    suite::{
        standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm},
        NoConfiguration,
    },
    ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::{
    protocol::{Base58Btc, WithProtocol},
    MessageSigner, SolanaMethod2021,
};
use static_iref::iri;

use crate::try_from_type;

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
/// The [`SolanaSignatureAlgorithm`] protocol is used.
#[derive(Debug, Default, Clone, Copy)]
pub struct SolanaSignature2021;

impl SolanaSignature2021 {
    pub const NAME: &'static str = "SolanaSignature2021";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#SolanaSignature2021");
}

impl StandardCryptographicSuite for SolanaSignature2021 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>; // ssi_jwk::algorithm::EdDSA, Base58Btc

    type VerificationMethod = SolanaMethod2021;

    type SignatureAlgorithm = SolanaSignatureAlgorithm;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(SolanaSignature2021);

// pub fn wallet_sign(message: &[u8], key: &JWK) -> Result<Vec<u8>, MessageSignatureError> {
//     let tx = LocalSolanaTransaction::with_message(message);
//     let bytes = tx.to_bytes();
//     let signature = ssi_jws::sign_bytes(ssi_jwk::Algorithm::EdDSA, &bytes, key)
//         .map_err(MessageSignatureError::signature_failed)?;
//     Ok(Base58Btc::encode_signature(&signature))
// }

pub struct SolanaSignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for SolanaSignatureAlgorithm {
    type Signature = Signature;
}

impl<T> SignatureAlgorithm<SolanaSignature2021, T> for SolanaSignatureAlgorithm
where
    T: MessageSigner<WithProtocol<ssi_jwk::Algorithm, Base58Btc>>,
{
    async fn sign(
        _verification_method: &SolanaMethod2021,
        _signer: T,
        _prepared_claims: [u8; 64],
        _proof_configuration: ProofConfigurationRef<'_, SolanaSignature2021>,
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }
}

impl VerificationAlgorithm<SolanaSignature2021> for SolanaSignatureAlgorithm {
    fn verify(
        method: &SolanaMethod2021,
        prepared_claims: [u8; 64],
        proof: ProofRef<SolanaSignature2021>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let tx = LocalSolanaTransaction::with_message(&prepared_claims);
        let signing_bytes = tx.to_bytes();

        let signature_bytes = Base58Btc::decode_signature(proof.signature.proof_value.as_bytes())
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        Ok(ssi_jws::verify_bytes(
            ssi_jwk::Algorithm::EdDSA,
            &signing_bytes,
            &method.public_key,
            &signature_bytes,
        )
        .map_err(|_| ssi_claims_core::InvalidProof::Signature))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    /// Base58Btc encoded signature.
    pub proof_value: String,
}

impl AsRef<str> for Signature {
    fn as_ref(&self) -> &str {
        &self.proof_value
    }
}

impl ssi_data_integrity_core::signing::AlterSignature for Signature {
    fn alter(&mut self) {
        self.proof_value.push_str("ff")
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
