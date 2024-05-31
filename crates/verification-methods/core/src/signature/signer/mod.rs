use ssi_claims_core::SignatureError;
use ssi_jwk::JWK;
use std::{borrow::Cow, marker::PhantomData};

pub mod local;
pub use local::LocalSigner;

pub mod single_secret;
pub use single_secret::SingleSecretSigner;

use crate::VerificationMethod;

/// Verification method signer.
pub trait Signer<M: VerificationMethod> {
    type MessageSigner;

    #[allow(async_fn_in_trait)]
    async fn for_method(&self, method: Cow<'_, M>) -> Option<Self::MessageSigner>;
}

impl<'s, M: VerificationMethod, S: Signer<M>> Signer<M> for &'s S {
    type MessageSigner = S::MessageSigner;

    async fn for_method(&self, method: Cow<'_, M>) -> Option<Self::MessageSigner> {
        S::for_method(*self, method).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
    #[error("0")]
    SignatureFailed(String),

    #[error("invalid signature client query")]
    InvalidQuery,

    #[error("invalid signer response")]
    InvalidResponse,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("missing signature algorithm")]
    MissingAlgorithm,

    #[error("unsupported signature algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("unsupported verification method `{0}`")]
    UnsupportedVerificationMethod(String),
}

impl MessageSignatureError {
    pub fn signature_failed(e: impl ToString) -> Self {
        Self::SignatureFailed(e.to_string())
    }
}

impl From<ssi_jwk::algorithm::AlgorithmError> for MessageSignatureError {
    fn from(value: ssi_jwk::algorithm::AlgorithmError) -> Self {
        match value {
            ssi_jwk::algorithm::AlgorithmError::Missing => Self::MissingAlgorithm,
            ssi_jwk::algorithm::AlgorithmError::Unsupported(a) => {
                Self::UnsupportedAlgorithm(a.to_string())
            }
        }
    }
}

impl From<ssi_jwk::algorithm::UnsupportedAlgorithm> for MessageSignatureError {
    fn from(value: ssi_jwk::algorithm::UnsupportedAlgorithm) -> Self {
        Self::UnsupportedAlgorithm(value.0.to_string())
    }
}

impl From<MessageSignatureError> for SignatureError {
    fn from(value: MessageSignatureError) -> Self {
        match value {
            MessageSignatureError::MissingAlgorithm => Self::MissingAlgorithm,
            MessageSignatureError::UnsupportedAlgorithm(name) => Self::UnsupportedAlgorithm(name),
            MessageSignatureError::InvalidSecretKey => Self::InvalidSecretKey,
            other => Self::other(other),
        }
    }
}

pub trait MessageSigner<A> {
    #[allow(async_fn_in_trait)]
    async fn sign(self, algorithm: A, message: &[u8]) -> Result<Vec<u8>, MessageSignatureError>;
}

impl<A: Into<ssi_jwk::Algorithm>> MessageSigner<A> for JWK {
    async fn sign(self, algorithm: A, message: &[u8]) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm.into(), message, &self)
            .map_err(MessageSignatureError::signature_failed)
    }
}

pub struct MessageSignerAdapter<S, A> {
    // Underlying signer.
    signer: S,

    algorithm: PhantomData<A>,
}

impl<S, A> MessageSignerAdapter<S, A> {
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            algorithm: PhantomData,
        }
    }
}

impl<S: MessageSigner<A>, A, B> MessageSigner<B> for MessageSignerAdapter<S, A>
where
    A: TryFrom<B>,
{
    async fn sign(self, algorithm: B, message: &[u8]) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)?;

        self.signer.sign(algorithm, message).await
    }
}
