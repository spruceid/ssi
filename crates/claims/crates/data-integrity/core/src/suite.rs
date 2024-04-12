//! Cryptographic suites.
use iref::Iri;
use ssi_claims_core::{ProofValidity, Verifiable};
use ssi_core::Referencable;
use ssi_crypto::MessageSigner;
use ssi_json_ld::JsonLdNodeObject;
use ssi_verification_methods_core::{
    InvalidVerificationMethod, SignatureError, Signer, VerificationError, VerificationMethod,
    VerificationMethodResolver,
};
use std::convert::Infallible;

use crate::{
    sign,
    signing::{self, sign_single},
    ExpandedConfiguration, ExpandedConfigurationRef, ExpandedType, Proof, ProofConfiguration,
    ProofConfigurationCastError, ProofConfigurationRefExpansion, ProofRef, Proofs,
    UnsupportedProofSuite,
};

#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    #[error("Expansion failed: {0}")]
    ExpansionFailed(String),

    #[error("RDF deserialization failed: {0}")]
    LinkedData(#[from] linked_data::IntoQuadsError),

    #[error("JSON serialization failed: {0}")]
    JsonSerialization(json_syntax::SerializeError),

    #[error("expected JSON object")] // TODO merge it with `InvalidData`.
    ExpectedJsonObject,

    #[error("invalid data")]
    InvalidData,

    #[error("unsupported input format")]
    UnsupportedInputFormat,

    #[error("invalid proof options: {0}")]
    InvalidProofOptions(InvalidOptions),

    #[error("invalid verification method: {0}")]
    InvalidVerificationMethod(InvalidVerificationMethod),

    #[error("internal error: `{0}`")]
    Internal(String),
}

impl From<ProofConfigurationCastError<InvalidVerificationMethod, InvalidOptions>>
    for TransformError
{
    fn from(value: ProofConfigurationCastError<InvalidVerificationMethod, InvalidOptions>) -> Self {
        match value {
            ProofConfigurationCastError::VerificationMethod(e) => {
                Self::InvalidVerificationMethod(e)
            }
            ProofConfigurationCastError::Options(e) => Self::InvalidProofOptions(e),
        }
    }
}

impl From<ProofConfigurationCastError<InvalidVerificationMethod, Infallible>> for TransformError {
    fn from(value: ProofConfigurationCastError<InvalidVerificationMethod, Infallible>) -> Self {
        match value {
            ProofConfigurationCastError::VerificationMethod(e) => {
                Self::InvalidVerificationMethod(e)
            }
            ProofConfigurationCastError::Options(_) => unreachable!(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("invalid verification method")]
    InvalidVerificationMethod,

    #[error("message is too long")]
    TooLong,

    #[error("invalid message: {0}")]
    InvalidMessage(Box<dyn 'static + std::error::Error>),

    #[error("invalid transformed input")]
    InvalidTransformedInput,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidOptions {
    #[error("missing public key")]
    MissingPublicKey,
}

impl From<InvalidOptions> for VerificationError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => VerificationError::MissingPublicKey,
        }
    }
}

impl From<InvalidOptions> for SignatureError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => SignatureError::MissingPublicKey,
        }
    }
}

pub trait CryptographicSuiteOptions<T>: Referencable {
    /// Prepare the options to be put in the generated proof.
    ///
    /// This means filtering out options that should not appear in the proof, or
    /// adding in implicit options values used to generate the proof that should
    /// explicitly appear in the proof.
    fn prepare(&mut self, _suite: &T) {
        // filter nothing.
    }
}

impl<T: CryptographicSuite> CryptographicSuiteOptions<T> for () {}

/// Cryptographic suite.
pub trait CryptographicSuite: Sized {
    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm result.
    type Hashed;

    /// Verification method.
    type VerificationMethod: VerificationMethod;

    /// Cryptography suite options used to generate the proof.
    type Options: CryptographicSuiteOptions<Self>;

    type MessageSignatureAlgorithm: Copy;

    type SignatureProtocol: ssi_crypto::SignatureProtocol<Self::MessageSignatureAlgorithm>;

    /// Signature.
    type Signature: Referencable;

    /// Returns the name of the cryptographic suite.
    fn name(&self) -> &str;

    /// Returns the type IRI of the cryptographic suite.
    fn iri(&self) -> &Iri;

    /// Refines the type of the cryptographic suite.
    ///
    /// When the crypto-suite type supports more than one suite with the same
    /// name, this function may be implemented to disambiguate and select the
    /// correct suite.
    fn refine_type(&mut self, type_: &Iri) -> Result<(), UnsupportedProofSuite> {
        if type_ == self.iri() {
            Ok(())
        } else {
            Err(UnsupportedProofSuite::Expanded(ExpandedType {
                iri: type_.to_owned(),
                cryptosuite: self.cryptographic_suite().map(ToOwned::to_owned),
            }))
        }
    }

    /// Returns the name of the cryptographic suite variant, if any.
    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError>;

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        None
    }

    /// Sign the hash.
    #[allow(async_fn_in_trait)]
    async fn sign_hash(
        &self,
        options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError>;

    /// Verify the given hash.
    fn verify_hash(
        &self,
        options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as Referencable>::Reference<'_>,
    ) -> Result<ProofValidity, VerificationError>;

    #[allow(async_fn_in_trait)]
    async fn generate_proof<S>(
        self,
        data: &Self::Hashed,
        resolver: &impl VerificationMethodResolver<Self::VerificationMethod>,
        signers: &S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Proof<Self>, SignatureError>
    where
        S: Signer<
            Self::VerificationMethod,
            Self::MessageSignatureAlgorithm,
            Self::SignatureProtocol,
        >,
    {
        let signature = {
            // Resolve the verification method.
            let verification_method = resolver
                .resolve_verification_method(None, Some(params.verification_method.borrowed()))
                .await?;

            // Find a signer for this verification method.
            let signer = signers
                .for_method(verification_method.as_reference())
                .await
                .ok_or(SignatureError::MissingSigner)?;

            self.sign_hash(
                params.options.as_reference(),
                verification_method.as_reference(),
                data,
                signer,
            )
            .await?
        };

        Ok(params.into_proof(self, signature))
    }

    #[allow(async_fn_in_trait)]
    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl VerificationMethodResolver<Self::VerificationMethod>,
        proof: ProofRef<'_, Self>,
    ) -> Result<ProofValidity, VerificationError> {
        // Resolve the verification method.
        let verification_method = verifier
            .resolve_verification_method(None, Some(proof.verification_method))
            .await?;

        self.verify_hash(
            proof.options,
            verification_method.as_reference(),
            data,
            proof.signature,
        )
    }
}

pub trait CryptographicSuiteInput<T, C = ()>: CryptographicSuite {
    // type Transform<'a>: 'a + Future<Output = Result<Self::Transformed, TransformError>>
    // where
    //     Self: 'a,
    //     T: 'a,
    //     C: 'a;

    /// Transformation algorithm.
    #[allow(async_fn_in_trait)]
    async fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: &'a mut C,
        params: ExpandedConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Transformed, TransformError>
    where
        C: 'a;

    #[allow(async_fn_in_trait)]
    async fn sign<'max, R, S>(
        self,
        input: T,
        context: C,
        resolver: &'max R,
        signer: &'max S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Verifiable<T, Proofs<Self>>, signing::Error<C::LoadError>>
    where
        Self::VerificationMethod: 'max,
        T: JsonLdNodeObject,
        R: 'max + VerificationMethodResolver<Self::VerificationMethod>,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm,
                Self::SignatureProtocol,
            >,
        C: for<'a> ProofConfigurationRefExpansion<'a, Self>,
    {
        sign(input, context, resolver, signer, self, params).await
    }

    #[allow(async_fn_in_trait)]
    async fn sign_single<'max, R, S>(
        self,
        input: T,
        context: C,
        resolver: &'max R,
        signer: &'max S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Verifiable<T, Proof<Self>>, signing::Error<C::LoadError>>
    where
        Self::VerificationMethod: 'max,
        T: JsonLdNodeObject,
        R: 'max + VerificationMethodResolver<Self::VerificationMethod>,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm,
                Self::SignatureProtocol,
            >,
        C: for<'a> ProofConfigurationRefExpansion<'a, Self>,
    {
        sign_single(input, context, resolver, signer, self, params).await
    }
}
