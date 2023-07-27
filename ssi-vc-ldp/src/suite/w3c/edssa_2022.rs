//! EdDSA Cryptosuite v2022 implementation.
//!
//! This is the successor of the EdDSA Cryptosuite v2020.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/>

use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_vc::ProofValidity;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration, ProofOptions,
    UntypedProof, UntypedProofRef,
};

use crate::suite::{sha256_hash, HashError};

pub use verification::method::Multikey;

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct EdDsa2022;

impl_rdf_input_urdna2015!(EdDsa2022);

#[async_trait::async_trait]
impl CryptographicSuite for EdDsa2022 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<Multikey>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#DataIntegrityProof")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        Some("eddsa-2022")
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
        let signature = signer.sign((), &options.verification_method, data)?;
        Ok(UntypedProof::from_options(options, signature.into()))
    }

    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl Verifier<Self::VerificationMethod>,
        proof: UntypedProofRef<'_, Self::VerificationMethod>,
    ) -> Result<ProofValidity, VerificationError> {
        let proof_value = proof
            .proof_value
            .as_multibase()
            .ok_or(VerificationError::InvalidProof)?;

        Ok(verifier
            .verify(
                (),
                proof.verification_method,
                proof.proof_purpose,
                data,
                proof_value,
            )
            .await?
            .into())
    }
}
