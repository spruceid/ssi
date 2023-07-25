use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_vc::ProofValidity;
use ssi_verification_methods::{RsaVerificationKey2018, Signature};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    verification, CryptographicSuite, ProofConfiguration, ProofOptions, UntypedProof,
    UntypedProofRef,
};

/// RSA Signature Suite 2018.
///
/// See: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaSignature2018;

impl_rdf_input_urdna2015!(RsaSignature2018);

#[async_trait::async_trait]
impl CryptographicSuite for RsaSignature2018 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<RsaVerificationKey2018>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#RsaSignature2018")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn generate_proof(
        &self,
        data: &Self::Hashed,
        signer: &impl Signer<Self::VerificationMethod>,
        options: ProofOptions<Self::VerificationMethod>,
    ) -> Result<UntypedProof<Self::VerificationMethod>, SignatureError> {
        let signature = signer.sign(&options.verification_method, data)?;
        Ok(UntypedProof::from_options(
            options,
            Signature::Base64(signature),
        ))
    }

    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl Verifier<Self::VerificationMethod>,
        proof: UntypedProofRef<'_, Self::VerificationMethod>,
    ) -> Result<ProofValidity, VerificationError> {
        let signature = proof
            .proof_value
            .as_base64()
            .ok_or(VerificationError::InvalidProof)?;

        Ok(verifier
            .verify(
                proof.verification_method,
                proof.proof_purpose,
                data,
                signature,
            )
            .await?
            .into())
    }
}
