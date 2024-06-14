//! Cryptographic suites.
use std::borrow::Cow;

use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_verification_methods_core::{Signer, VerificationMethodResolver, VerificationMethodSet};

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
    ClaimsPreparationError, ConfigurationAlgorithm, CryptographicSuiteInstance,
    CryptographicSuiteSigning, CryptographicSuiteVerification,
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

    /// Verification method.
    type VerificationMethod: VerificationMethodSet;

    /// Signature (and verification) algorithm.
    type SignatureAlgorithm: SignatureAndVerificationAlgorithm + VerificationAlgorithm<Self>;

    /// Cryptography suite options appearing in the proof.
    type ProofOptions;

    /// Returns the cryptographic suite type.
    fn type_(&self) -> TypeRef;

    #[allow(async_fn_in_trait)]
    async fn transform<T, C>(
        &self,
        context: &mut C,
        unsecured_document: &T,
        options: ProofConfigurationRef<'_, Self>,
    ) -> Result<TransformedData<Self>, TransformationError>
    where
        Self::Transformation: TypedTransformationAlgorithm<Self, T, C>,
    {
        Self::Transformation::transform(context, unsecured_document, options).await
    }

    fn hash(
        &self,
        transformed_document: TransformedData<Self>,
        proof_configuration: ProofConfigurationRef<'_, Self>,
    ) -> Result<HashedData<Self>, HashingError> {
        Self::Hashing::hash(transformed_document, proof_configuration)
    }
}

impl<S: StandardCryptographicSuite> CryptographicSuite for S {
    /// How to represent prepared claims.
    type PreparedClaims = HashedData<S>;

    /// Configuration algorithm, used to generate the proof configuration from
    /// the input options.
    type Configuration = S::Configuration;

    /// Verification method.
    type VerificationMethod = S::VerificationMethod;

    /// Cryptography suite options used to generate the proof.
    type ProofOptions = S::ProofOptions;

    /// Signature type.
    ///
    /// For cryptographic suites conforming to the most recent iteration of
    /// the Data-Integrity specification, this will be [`ProofValue`].
    type Signature = <S::SignatureAlgorithm as SignatureAndVerificationAlgorithm>::Signature;

    /// Returns the cryptographic suite type.
    fn type_(&self) -> TypeRef {
        StandardCryptographicSuite::type_(self)
    }
}

impl<S: StandardCryptographicSuite, R, T> CryptographicSuiteSigning<R, T> for S
where
    R: VerificationMethodResolver<Method = Self::VerificationMethod>,
    T: Signer<<Self as StandardCryptographicSuite>::VerificationMethod>,
    S::SignatureAlgorithm: SignatureAlgorithm<S, T::MessageSigner>,
{
    async fn sign_prepared_claims(
        &self,
        resolver: R,
        signers: T,
        prepared_claims: &Self::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, Self>,
    ) -> Result<Self::Signature, SignatureError> {
        let options = ssi_verification_methods_core::ResolutionOptions {
            accept: Some(Box::new(Self::VerificationMethod::type_set())),
        };

        // Resolve the verification method.
        let method = resolver
            .resolve_verification_method_with(
                None,
                Some(proof_configuration.verification_method),
                options,
            )
            .await?;

        // Find a signer for this verification method.
        let signer = signers
            .for_method(Cow::Borrowed(&method))
            .await
            .ok_or(SignatureError::MissingSigner)?;

        S::SignatureAlgorithm::sign(&method, signer, prepared_claims, proof_configuration).await
    }
}

impl<S: StandardCryptographicSuite, V> CryptographicSuiteVerification<V> for S
where
    V: VerificationMethodResolver<Method = S::VerificationMethod>,
    S::SignatureAlgorithm: VerificationAlgorithm<S>,
{
    async fn verify_prepared_claims(
        &self,
        verifier: &V,
        prepared_claims: &Self::PreparedClaims,
        proof: ProofRef<'_, Self>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let options = ssi_verification_methods_core::ResolutionOptions {
            accept: Some(Box::new(Self::VerificationMethod::type_set())),
        };

        // Resolve the verification method.
        let method = verifier
            .resolve_verification_method_with(None, Some(proof.verification_method), options)
            .await?;

        S::SignatureAlgorithm::verify(&method, prepared_claims, proof)
    }
}

impl<S: StandardCryptographicSuite, T, C> CryptographicSuiteInstance<T, C> for S
where
    S::Transformation: TypedTransformationAlgorithm<S, T, C>,
{
    async fn prepare_claims(
        &self,
        context: &mut C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, Self>,
    ) -> Result<Self::PreparedClaims, ClaimsPreparationError> {
        // Transform unsecured document.
        let transformed = self
            .transform(context, unsecured_document, proof_configuration)
            .await?;

        // Hashing.
        self.hash(transformed, proof_configuration)
            .map_err(Into::into)
    }
}
