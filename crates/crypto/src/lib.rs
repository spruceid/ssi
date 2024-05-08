#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod hashes;
pub mod protocol;
pub mod signatures;

pub use protocol::SignatureProtocol;
use std::marker::PhantomData;

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
