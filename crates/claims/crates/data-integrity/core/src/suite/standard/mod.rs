//! Cryptographic suites.
use std::borrow::Cow;

use ssi_claims_core::{
    ProofValidationError, ProofValidity, VerificationParameters
};
use ssi_crypto::{Issuer, SignatureError, Signer, Verifier};
use ssi_verification_methods::{GetVerificationMethod, VerificationMethod, VerificationMethodIssuer, VerificationMethodVerifierRegistry};

use crate::{CryptographicSuite, ProofConfigurationRef, ProofRef, TypeRef};

mod transformation;
pub use transformation::*;

mod hashing;
pub use hashing::*;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

use super::{
    ConfigurationAlgorithm, CryptographicSuiteSigning, CryptographicSuiteVerification,
    TransformationOptions,
};

// mod test_bbs;

/// Standard cryptographic suite.
///
/// This trait definition encapsulate the requirements for all data integrity
/// cryptographic suite specifications.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites>
pub trait StandardCryptographicSuite: Clone {
    /// Configuration algorithm.
    type Configuration: ConfigurationAlgorithm<Self>;

    /// Transformation algorithm.
    type Transformation: TransformationAlgorithm<Self>;

    /// Hashing algorithm result.
    type Hashing: HashingAlgorithm<Self>;

    /// Signature (and verification) algorithm.
    type SignatureAlgorithm: SignatureAndVerificationAlgorithm + VerificationAlgorithm<Self>;

    /// Cryptography suite options appearing in the proof.
    type ProofOptions;

    /// Returns the cryptographic suite type.
    fn type_(&self) -> TypeRef;

    #[allow(async_fn_in_trait)]
    async fn transform<T>(
        &self,
        // context: &C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, Self>,
        verification_method: &VerificationMethod,
        transformation_options: TransformationOptions<Self>,
    ) -> Result<TransformedData<Self>, TransformationError>
    where
        Self::Transformation: TypedTransformationAlgorithm<Self, T>,
    {
        Self::Transformation::transform(
            // context,
            unsecured_document,
            proof_configuration,
            verification_method,
            transformation_options,
        )
        .await
    }

    fn hash(
        &self,
        transformed_document: TransformedData<Self>,
        proof_configuration: ProofConfigurationRef<'_, Self>,
        verification_method: &VerificationMethod,
    ) -> Result<HashedData<Self>, HashingError> {
        Self::Hashing::hash(
            transformed_document,
            proof_configuration,
            verification_method,
        )
    }
}

impl<S: StandardCryptographicSuite> CryptographicSuite for S {
    /// How to represent prepared claims.
    type PreparedClaims = HashedData<S>;

    /// Configuration algorithm, used to generate the proof configuration from
    /// the input options.
    type Configuration = S::Configuration;

    /// Cryptography suite options used to generate the proof.
    type ProofOptions = S::ProofOptions;

    /// Signature type.
    ///
    /// For cryptographic suites conforming to the most recent iteration of
    /// the Data-Integrity specification, this will be `proofValue`.
    type Signature = <S::SignatureAlgorithm as SignatureAndVerificationAlgorithm>::Signature;

    /// Returns the cryptographic suite type.
    fn type_(&self) -> TypeRef {
        StandardCryptographicSuite::type_(self)
    }
}

impl<C, S: StandardCryptographicSuite> CryptographicSuiteSigning<C> for S
where
    S::Transformation: TypedTransformationAlgorithm<Self, C>,
    S::SignatureAlgorithm: SignatureAlgorithm<S>,
{
    async fn generate_signature(
        &self,
        context: &VerificationParameters,
        signers: impl VerificationMethodIssuer,
        claims: &C,
        proof_configuration: ProofConfigurationRef<'_, Self>,
        transformation_options: TransformationOptions<Self>,
    ) -> Result<Self::Signature, SignatureError> {
        // let options = ssi_verification_methods::ResolutionOptions {
        //     accept: Some(Box::new(Self::VerificationMethod::type_set())),
        // };

        // Resolve the verification method.
        let signer = signers
            .require_key(Some(proof_configuration.verification_method.id().as_bytes()))
            .await?;

        let method = signer.get_verification_method();

        let transformed = self
            .transform(
                // context,
                claims,
                proof_configuration,
                &method,
                transformation_options,
            )
            .await?;

        let hashed = self.hash(transformed, proof_configuration, &method)?;

        S::SignatureAlgorithm::sign(&method, signer, hashed, proof_configuration).await
    }
}

impl<S: StandardCryptographicSuite, C> CryptographicSuiteVerification<C> for S
where
    S::Transformation: TypedTransformationAlgorithm<Self, C>,
    S::SignatureAlgorithm: VerificationAlgorithm<S>,
{
    async fn verify_proof(
        &self,
        verifier_registry: impl VerificationMethodVerifierRegistry,
        claims: &C,
        proof: ProofRef<'_, Self>,
        transformation_options: TransformationOptions<S>,
    ) -> Result<ProofValidity, ProofValidationError> {
        // let options = ssi_verification_methods::ResolutionOptions {
        //     accept: Some(Box::new(Self::VerificationMethod::type_set())),
        // };

        // Resolve the verification method.
        let signer = verifier_registry
            .require_key(Some(proof_configuration.verification_method.id().as_bytes()))
            .await?;

        let method = signer.get_verification_method();

        let proof_configuration = proof.configuration();

        let transformed = self
            .transform(
                // verifier,
                claims,
                proof_configuration,
                &method,
                transformation_options,
            )
            .await?;

        let hashed = self.hash(transformed, proof_configuration, &method)?;

        S::SignatureAlgorithm::verify(&method, hashed, proof)
    }
}
