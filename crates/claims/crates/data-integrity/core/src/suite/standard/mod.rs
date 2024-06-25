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

use super::{ConfigurationAlgorithm, CryptographicSuiteSigning, CryptographicSuiteVerification};

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
        context: &C,
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

impl<C, E, R, T, S: StandardCryptographicSuite> CryptographicSuiteSigning<C, E, R, T> for S
where
    R: VerificationMethodResolver<Method = Self::VerificationMethod>,
    T: Signer<<Self as StandardCryptographicSuite>::VerificationMethod>,
    S::Transformation: TypedTransformationAlgorithm<Self, C, E>,
    S::SignatureAlgorithm: SignatureAlgorithm<S, T::MessageSigner>,
{
    async fn generate_signature(
        &self,
        context: &E,
        resolver: R,
        signers: T,
        claims: &C,
        proof_configuration: ProofConfigurationRef<'_, Self>,
    ) -> Result<Self::Signature, SignatureError> {
        let transformed = self.transform(context, claims, proof_configuration).await?;

        let hashed = self.hash(transformed, proof_configuration)?;

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

        S::SignatureAlgorithm::sign(&method, signer, hashed, proof_configuration).await
    }
}

impl<S: StandardCryptographicSuite, C, E, V> CryptographicSuiteVerification<C, E, V> for S
where
    V: VerificationMethodResolver<Method = S::VerificationMethod>,
    S::Transformation: TypedTransformationAlgorithm<Self, C, E>,
    S::SignatureAlgorithm: VerificationAlgorithm<S>,
{
    async fn verify_proof(
        &self,
        context: &E,
        verifier: &V,
        claims: &C,
        proof: ProofRef<'_, Self>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let proof_configuration = proof.configuration();

        let transformed = self.transform(context, claims, proof_configuration).await?;

        let hashed = self.hash(transformed, proof_configuration)?;

        let options = ssi_verification_methods_core::ResolutionOptions {
            accept: Some(Box::new(Self::VerificationMethod::type_set())),
        };

        // Resolve the verification method.
        let method = verifier
            .resolve_verification_method_with(None, Some(proof.verification_method), options)
            .await?;

        S::SignatureAlgorithm::verify(&method, hashed, proof)
    }
}
