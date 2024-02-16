//! Cryptographic suites.
use iref::Iri;
use ssi_claims_core::{ProofValidity, Verifiable};
use ssi_core::Referencable;
use ssi_json_ld::WithJsonLdContext;
use ssi_verification_methods::{
    InvalidVerificationMethod, SignatureAlgorithm, SignatureError, Signer, VerificationError,
    VerificationMethod, Verifier,
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
    #[error("Expansion failed")]
    ExpansionFailed,

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

pub trait FromRdfAndSuite<S> {
    // ...
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
    type Hashed: AsRef<[u8]>;

    /// Verification method.
    type VerificationMethod: VerificationMethod;

    /// Cryptography suite options used to generate the proof.
    type Options: CryptographicSuiteOptions<Self>;

    /// Signature.
    type Signature: Referencable;

    type MessageSignatureAlgorithm: Copy;

    type SignatureProtocol: ssi_crypto::SignatureProtocol<Self::MessageSignatureAlgorithm>;

    /// Signature algorithm.
    type SignatureAlgorithm: SignatureAlgorithm<
        Self::VerificationMethod,
        Options = Self::Options,
        Signature = Self::Signature,
        MessageSignatureAlgorithm = Self::MessageSignatureAlgorithm,
        Protocol = Self::SignatureProtocol,
    >;

    fn name(&self) -> &str;

    fn iri(&self) -> &Iri;

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

    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError>;

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm;

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        None
    }

    #[allow(async_fn_in_trait)]
    async fn generate_proof<'a, S>(
        self,
        data: &'a Self::Hashed,
        signer: &'a S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Proof<Self>, SignatureError>
    where
        S: Signer<
            Self::VerificationMethod,
            Self::MessageSignatureAlgorithm,
            Self::SignatureProtocol,
        >,
    {
        let algorithm = self.setup_signature_algorithm();
        let signature = signer
            .sign(
                algorithm,
                params.options.as_reference(),
                None,
                Some(params.verification_method.borrowed()),
                data.as_ref(),
            )
            .await?;

        Ok(params.into_proof(self, signature))
    }

    #[allow(async_fn_in_trait)]
    async fn verify_proof<'a, 'p: 'a, V: Verifier<Self::VerificationMethod>>(
        &self,
        data: &'a Self::Hashed,
        verifier: &'a V,
        proof: ProofRef<'a, Self>,
    ) -> Result<ProofValidity, VerificationError> {
        let algorithm = self.setup_signature_algorithm();
        verifier
            .verify(
                algorithm,
                proof.options,
                None,
                Some(proof.verification_method),
                proof.proof_purpose,
                data.as_ref(),
                proof.signature,
            )
            .await
            .map(Into::into)
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
    async fn sign<'max, S>(
        self,
        input: T,
        context: C,
        signer: &'max S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Verifiable<T, Proofs<Self>>, signing::Error<C::LoadError>>
    where
        Self::VerificationMethod: 'max,
        T: WithJsonLdContext,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm,
                Self::SignatureProtocol,
            >,
        C: for<'a> ProofConfigurationRefExpansion<'a, Self>,
    {
        sign(input, context, signer, self, params).await
    }

    #[allow(async_fn_in_trait)]
    async fn sign_single<'max, S>(
        self,
        input: T,
        context: C,
        signer: &'max S,
        params: ProofConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Verifiable<T, Proof<Self>>, signing::Error<C::LoadError>>
    where
        Self::VerificationMethod: 'max,
        T: WithJsonLdContext,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm,
                Self::SignatureProtocol,
            >,
        C: for<'a> ProofConfigurationRefExpansion<'a, Self>,
    {
        sign_single(input, context, signer, self, params).await
    }
}
