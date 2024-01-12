#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod hashes;
pub mod protocol;
pub mod signatures;

use std::{future::Future, marker::PhantomData};

use pin_project::pin_project;
pub use protocol::SignatureProtocol;

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
    async fn sign(self, algorithm: A, protocol: P, message: &[u8]) -> Result<Vec<u8>, MessageSignatureError>;
}

// impl<'a, F, P: SignatureProtocol> MessageSigner<'a, P> for F
// where
//     P::Output: 'a,
//     F: 'a + FnOnce(P, &'a [u8]) -> Result<P::Output, MessageSignatureError>,
// {
//     type Sign = future::Ready<Result<P::Output, MessageSignatureError>>;

//     fn sign(self, protocol: P, message: &'a [u8]) -> Self::Sign {
//         future::ready((self)(protocol, message))
//     }
// }

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
    async fn sign(self, algorithm: B, protocol: Q, message: &[u8]) -> Result<Vec<u8>, MessageSignatureError> {
        match algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)
        {
            Ok(algorithm) => {
                match protocol
                    .try_into()
                    .map_err(|_| MessageSignatureError::InvalidQuery)
                {
                    Ok(protocol) => {
                        self.signer.sign(algorithm, protocol, message).await
                    },
                    Err(e) => Err(e)
                }
            }
            Err(e) => Err(e)
        }
    }
}

// #[pin_project]
// pub struct SignerAdapterSign<
//     'a,
//     S: MessageSigner<A, P>,
//     A,
//     B,
//     P: SignatureProtocol<A>,
//     Q: SignatureProtocol<B>,
// > {
//     #[pin]
//     inner: SignerAdapterSignInner<'a, S, A, B, P, Q>,
// }

// impl<'a, S: MessageSigner<A, P>, A, B, P: SignatureProtocol<A>, Q: SignatureProtocol<B>> Future
//     for SignerAdapterSign<'a, S, A, B, P, Q>
// {
//     type Output = Result<Vec<u8>, MessageSignatureError>;

//     fn poll(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Self::Output> {
//         let this = self.project();
//         this.inner.poll(cx)
//     }
// }

// #[pin_project(project = SignerAdapterSignProj)]
// enum SignerAdapterSignInner<
//     'a,
//     S: MessageSigner<A, P>,
//     A,
//     B,
//     P: SignatureProtocol<A>,
//     Q: SignatureProtocol<B>,
// > {
//     Ok(#[pin] SignerAdapterSignOk<'a, S, A, B, P, Q>),
//     Err(Option<MessageSignatureError>),
// }

// impl<'a, S: MessageSigner<A, P>, A, B, P: SignatureProtocol<A>, Q: SignatureProtocol<B>> Future
//     for SignerAdapterSignInner<'a, S, A, B, P, Q>
// {
//     type Output = Result<Vec<u8>, MessageSignatureError>;

//     fn poll(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Self::Output> {
//         match self.project() {
//             SignerAdapterSignProj::Ok(f) => f.poll(cx),
//             SignerAdapterSignProj::Err(e) => std::task::Poll::Ready(Err(e.take().unwrap())),
//         }
//     }
// }

// #[pin_project]
// pub struct SignerAdapterSignOk<
//     'a,
//     S: 'a + MessageSigner<A, P>,
//     A: 'a,
//     B,
//     P: 'a + SignatureProtocol<A>,
//     Q: SignatureProtocol<B>,
// > {
//     #[pin]
//     inner: S::Sign<'a>,
//     pq: PhantomData<(A, B, P, Q)>,
// }

// impl<'a, S: MessageSigner<A, P>, A, B, P: SignatureProtocol<A>, Q: SignatureProtocol<B>> Future
//     for SignerAdapterSignOk<'a, S, A, B, P, Q>
// {
//     type Output = Result<Vec<u8>, MessageSignatureError>;

//     fn poll(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Self::Output> {
//         let this = self.project();
//         this.inner.poll(cx)
//     }
// }
