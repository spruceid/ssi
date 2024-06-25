use ssi_claims_core::{
    ProofPreparationError, ProofValidationError, SignatureEnvironment, SignatureError,
};
use ssi_verification_methods_core::VerificationMethod;

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
    /// the Data-Integrity specification, this will be [`ProofValue`].
    type Signature: AsRef<str>;

    /// Returns the cryptographic suite type.
    fn type_(&self) -> TypeRef;

    /// Generates a proof configuration from input options.
    fn configure(
        &self,
        options: InputOptions<Self>,
    ) -> Result<ProofConfiguration<Self>, ConfigurationError> {
        Self::Configuration::configure(self, options)
    }

    /// Generates a verifiable document secured with this cryptographic suite.
    #[allow(async_fn_in_trait)]
    async fn sign_with<T, C, R, S>(
        &self,
        context: C,
        unsecured_document: T,
        resolver: R,
        signer: S,
        options: InputOptions<Self>,
    ) -> Result<DataIntegrity<T, Self>, SignatureError>
    where
        Self: CryptographicSuiteSigning<T, C, R, S>,
    {
        let proof_configuration = self.configure(options)?;
        let proof_configuration_ref = proof_configuration.borrowed();
        let signature = self
            .generate_signature(
                &context,
                resolver,
                signer,
                &unsecured_document,
                proof_configuration_ref,
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
        options: InputOptions<Self>,
    ) -> Result<DataIntegrity<T, Self>, SignatureError>
    where
        Self: CryptographicSuiteSigning<T, SignatureEnvironment, R, S>,
    {
        self.sign_with(
            SignatureEnvironment::default(),
            unsecured_document,
            resolver,
            signer,
            options,
        )
        .await
    }
}

// /// Cryptographic suite instance.
// ///
// /// See: <https://www.w3.org/TR/vc-data-integrity/#dfn-data-integrity-cryptographic-suite-instance>
// pub trait CryptographicSuiteInstance<T, C = ()>: CryptographicSuite {
//     /// Prepare the input claims for signing or verification.
//     #[allow(async_fn_in_trait)]
//     async fn prepare_claims(
//         &self,
//         context: &mut C,
//         unsecured_document: &T,
//         proof_configuration: ProofConfigurationRef<Self>,
//     ) -> Result<Self::PreparedClaims, ClaimsPreparationError>;

//     /// Create a proof by signing the given unsecured document.
//     #[allow(async_fn_in_trait)]
//     async fn create_proof<R, S>(
//         &self,
//         context: &mut C,
//         resolver: R,
//         signer: S,
//         unsecured_document: &T,
//         options: InputOptions<Self>,
//     ) -> Result<Proof<Self>, SignatureError>
//     where
//         Self: CryptographicSuiteSigning<R, S>,
//     {
//         let proof_configuration = self.configure(options)?;
//         let proof_configuration_ref = proof_configuration.borrowed();
//         let prepared_claims = self
//             .prepare_claims(context, unsecured_document, proof_configuration_ref)
//             .await?;
//         let signature = self
//             .sign_prepared_claims(resolver, signer, &prepared_claims, proof_configuration_ref)
//             .await?;
//         Ok(proof_configuration.into_proof(signature))
//     }

//     /// Verify a proof of the given unsecured document.
//     #[allow(async_fn_in_trait)]
//     async fn verify_proof<V>(
//         &self,
//         context: &mut C,
//         verifier: &V,
//         unsecured_document: &T,
//         proof: ProofRef<'_, Self>,
//     ) -> Result<ProofValidity, ProofValidationError>
//     where
//         Self: CryptographicSuiteVerification<V>,
//     {
//         let prepared_claims = self
//             .prepare_claims(context, unsecured_document, proof.configuration())
//             .await?;
//         self.verify_prepared_claims(verifier, &prepared_claims, proof)
//             .await
//     }
// }

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
