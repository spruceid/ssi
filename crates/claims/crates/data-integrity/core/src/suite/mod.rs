use ssi_claims_core::{
    ProofPreparationError, ProofValidationError, SignatureEnvironment, SignatureError,
};
use ssi_verification_methods::VerificationMethod;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

use crate::{DataIntegrity, ProofConfiguration, TypeRef};

mod configuration;
pub use configuration::*;

pub mod bounds;
pub use bounds::{
    CloneCryptographicSuite, DebugCryptographicSuite, DeserializeCryptographicSuite,
    DeserializeCryptographicSuiteOwned, SerializeCryptographicSuite,
};

use self::standard::{HashingError, TransformationError};

pub mod standard;
pub use standard::StandardCryptographicSuite;

mod sd;
pub use sd::*;

/// Cryptographic suite.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites>
pub trait CryptographicSuite: Clone {
    /// How prepared claims are stored.
    ///
    /// This is the output of the hashing algorithm.
    type PreparedClaims;

    /// Configuration algorithm, used to generate the proof configuration from
    /// the input options.
    ///
    /// Most cryptographic suites will just use the input options as proof
    /// configuration. Some suites may also use this step to add a custom
    /// `@context` definition to the proof.
    type Configuration: ConfigurationAlgorithm<Self>;

    /// Verification method.
    type VerificationMethod: VerificationMethod;

    /// Suite-specific proof options used to generate the proof.
    type ProofOptions;

    /// Signature type.
    ///
    /// For cryptographic suites conforming to the most recent iteration of
    /// the Data-Integrity specification, this will be `proofValue`.
    type Signature: AsRef<str>;

    /// Returns the cryptographic suite type.
    fn type_(&self) -> TypeRef;

    /// Generates a proof configuration from input options.
    fn configure_signature(
        &self,
        proof_options: InputProofOptions<Self>,
        signature_options: InputSignatureOptions<Self>,
    ) -> Result<(ProofConfiguration<Self>, TransformationOptions<Self>), ConfigurationError> {
        Self::Configuration::configure_signature(self, proof_options, signature_options)
    }

    /// Generates a proof configuration from input options.
    fn configure_verification(
        &self,
        verification_options: &InputVerificationOptions<Self>,
    ) -> Result<TransformationOptions<Self>, ConfigurationError> {
        Self::Configuration::configure_verification(self, verification_options)
    }

    /// Generates a verifiable document secured with this cryptographic suite.
    #[allow(async_fn_in_trait)]
    async fn sign_with<T, C, R, S>(
        &self,
        context: C,
        unsecured_document: T,
        resolver: R,
        signer: S,
        proof_options: InputProofOptions<Self>,
        signature_options: InputSignatureOptions<Self>,
    ) -> Result<DataIntegrity<T, Self>, SignatureError>
    where
        Self: CryptographicSuiteSigning<T, C, R, S>,
    {
        let (proof_configuration, transformation_options) =
            self.configure_signature(proof_options, signature_options)?;
        let proof_configuration_ref = proof_configuration.borrowed();
        let signature = self
            .generate_signature(
                &context,
                resolver,
                signer,
                &unsecured_document,
                proof_configuration_ref,
                transformation_options,
            )
            .await?;

        let proof = proof_configuration.into_proof(signature);
        Ok(DataIntegrity::new(unsecured_document, proof.into()))
    }

    /// Generates a verifiable document secured with this cryptographic suite.
    #[allow(async_fn_in_trait)]
    async fn sign<T, R, S>(
        &self,
        unsecured_document: T,
        resolver: R,
        signer: S,
        proof_options: InputProofOptions<Self>,
    ) -> Result<DataIntegrity<T, Self>, SignatureError>
    where
        Self: CryptographicSuiteSigning<T, SignatureEnvironment, R, S>,
        InputSignatureOptions<Self>: Default,
    {
        self.sign_with(
            SignatureEnvironment::default(),
            unsecured_document,
            resolver,
            signer,
            proof_options,
            Default::default(),
        )
        .await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimsPreparationError {
    #[error("proof configuration failed: {0}")]
    Configuration(#[from] ConfigurationError),

    #[error("claims transformation failed: {0}")]
    Transformation(#[from] TransformationError),

    #[error("hashing failed: {0}")]
    Hashing(#[from] HashingError),
}

impl From<ClaimsPreparationError> for SignatureError {
    fn from(value: ClaimsPreparationError) -> Self {
        Self::other(value)
    }
}

impl From<ClaimsPreparationError> for ProofValidationError {
    fn from(value: ClaimsPreparationError) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<ClaimsPreparationError> for ProofPreparationError {
    fn from(value: ClaimsPreparationError) -> Self {
        Self::Claims(value.to_string())
    }
}
