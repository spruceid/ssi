//! Cryptographic suites.
use std::borrow::Cow;

use ssi_claims_core::{
    ProofValidationError, ProofValidity, ResolverProvider, ResourceProvider, SignatureError,
};
use ssi_verification_methods::{Signer, VerificationMethodResolver, VerificationMethodSet};

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
    InputVerificationOptions, TransformationOptions,
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
        context: &C,
        unsecured_document: &T,
        proof_configuration: ProofConfigurationRef<'_, Self>,
        verification_method: &Self::VerificationMethod,
        transformation_options: TransformationOptions<Self>,
    ) -> Result<TransformedData<Self>, TransformationError>
    where
        Self::Transformation: TypedTransformationAlgorithm<Self, T, C>,
    {
        Self::Transformation::transform(
            context,
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
        verification_method: &Self::VerificationMethod,
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

    /// Verification method.
    type VerificationMethod = S::VerificationMethod;

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
        transformation_options: TransformationOptions<Self>,
    ) -> Result<Self::Signature, SignatureError> {
        let options = ssi_verification_methods::ResolutionOptions {
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

        let transformed = self
            .transform(
                context,
                claims,
                proof_configuration,
                &method,
                transformation_options,
            )
            .await?;

        let hashed = self.hash(transformed, proof_configuration, &method)?;

        // Find a signer for this verification method.
        let signer = signers
            .for_method(Cow::Borrowed(&method))
            .await?
            .ok_or(SignatureError::MissingSigner)?;

        S::SignatureAlgorithm::sign(&method, signer, hashed, proof_configuration).await
    }
}

impl<S: StandardCryptographicSuite, C, V> CryptographicSuiteVerification<C, V> for S
where
    V: ResolverProvider + ResourceProvider<InputVerificationOptions<S>>,
    V::Resolver: VerificationMethodResolver<Method = S::VerificationMethod>,
    S::Transformation: TypedTransformationAlgorithm<Self, C, V>,
    S::SignatureAlgorithm: VerificationAlgorithm<S>,
{
    async fn verify_proof(
        &self,
        verifier: &V,
        claims: &C,
        proof: ProofRef<'_, Self>,
        transformation_options: TransformationOptions<S>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let options = ssi_verification_methods::ResolutionOptions {
            accept: Some(Box::new(Self::VerificationMethod::type_set())),
        };

        // Resolve the verification method.
        let method = verifier
            .resolver()
            .resolve_verification_method_with(None, Some(proof.verification_method), options)
            .await?;

        let proof_configuration = proof.configuration();

        let transformed = self
            .transform(
                verifier,
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
