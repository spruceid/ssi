use crate::SignatureProtocol;
use ssi_claims_core::SignatureError;
use ssi_core::Referencable;
use std::marker::PhantomData;

pub mod single_secret;
pub use single_secret::SingleSecretSigner;

/// Verification method signer.
///
/// `M` is the verification method type.
/// `B` is the cryptographic signature algorithm to be used with the verification method.
/// `P` is the signature protocol.
pub trait Signer<M: Referencable, A, P: SignatureProtocol<A> = ()> {
    type MessageSigner<'a>: MessageSigner<A, P>
    where
        Self: 'a,
        M: 'a;

    #[allow(async_fn_in_trait)]
    async fn for_method<'a>(&'a self, method: M::Reference<'a>) -> Option<Self::MessageSigner<'a>>;
}

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
    #[error(transparent)]
    SignatureFailed(Box<dyn 'static + std::error::Error>),

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
}

impl MessageSignatureError {
    pub fn signature_failed<E: 'static + std::error::Error>(e: E) -> Self {
        Self::SignatureFailed(Box::new(e))
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

pub trait MessageSigner<A, P: SignatureProtocol<A> = ()> {
    #[allow(async_fn_in_trait)]
    async fn sign(
        self,
        algorithm: A,
        protocol: P,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError>;
}

pub struct SignerAdapter<S, A, P> {
    // Underlying signer.
    signer: S,

    protocol: PhantomData<(A, P)>,
}

impl<S, A, P> SignerAdapter<S, A, P> {
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            protocol: PhantomData,
        }
    }
}

impl<S: MessageSigner<A, P>, A, B, P: SignatureProtocol<A>, Q: SignatureProtocol<B>>
    MessageSigner<B, Q> for SignerAdapter<S, A, P>
where
    P: TryFrom<Q>,
    A: TryFrom<B>,
{
    async fn sign(
        self,
        algorithm: B,
        protocol: Q,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)
        {
            Ok(algorithm) => {
                match protocol
                    .try_into()
                    .map_err(|_| MessageSignatureError::InvalidQuery)
                {
                    Ok(protocol) => self.signer.sign(algorithm, protocol, message).await,
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}
