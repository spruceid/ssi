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
}

impl MessageSignatureError {
    pub fn signature_failed<E: 'static + std::error::Error>(e: E) -> Self {
        Self::SignatureFailed(Box::new(e))
    }
}

pub trait MessageSigner<P: SignatureProtocol = ()> {
    type Sign<'a>: 'a + Future<Output = Result<Vec<u8>, MessageSignatureError>>
    where
        Self: 'a,
        P: 'a;

    fn sign<'a>(self, protocol: P, message: &'a [u8]) -> Self::Sign<'a>
    where
        Self: 'a,
        P: 'a;
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

pub struct SignerAdapter<S, P> {
    // Underlying signer.
    signer: S,

    protocol: PhantomData<P>,
}

impl<S, P> SignerAdapter<S, P> {
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            protocol: PhantomData,
        }
    }
}

impl<S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> MessageSigner<Q>
    for SignerAdapter<S, P>
where
    P: TryFrom<Q>,
{
    type Sign<'a> = SignerAdapterSign<'a, S, P, Q> where Self: 'a, Q: 'a;

    fn sign<'a>(self, protocol: Q, message: &'a [u8]) -> Self::Sign<'a>
    where
        Self: 'a,
        Q: 'a,
    {
        let inner = match protocol
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)
        {
            Ok(protocol) => SignerAdapterSignInner::Ok(SignerAdapterSignOk {
                inner: self.signer.sign(protocol, message),
                pq: PhantomData,
            }),
            Err(e) => SignerAdapterSignInner::Err(Some(e)),
        };

        SignerAdapterSign { inner }
    }
}

#[pin_project]
pub struct SignerAdapterSign<'a, S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> {
    #[pin]
    inner: SignerAdapterSignInner<'a, S, P, Q>,
}

impl<'a, S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> Future
    for SignerAdapterSign<'a, S, P, Q>
{
    type Output = Result<Vec<u8>, MessageSignatureError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}

#[pin_project(project = SignerAdapterSignProj)]
enum SignerAdapterSignInner<'a, S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> {
    Ok(#[pin] SignerAdapterSignOk<'a, S, P, Q>),
    Err(Option<MessageSignatureError>),
}

impl<'a, S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> Future
    for SignerAdapterSignInner<'a, S, P, Q>
{
    type Output = Result<Vec<u8>, MessageSignatureError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project() {
            SignerAdapterSignProj::Ok(f) => f.poll(cx),
            SignerAdapterSignProj::Err(e) => std::task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

#[pin_project]
pub struct SignerAdapterSignOk<
    'a,
    S: 'a + MessageSigner<P>,
    P: 'a + SignatureProtocol,
    Q: SignatureProtocol,
> {
    #[pin]
    inner: S::Sign<'a>,
    pq: PhantomData<(P, Q)>,
}

impl<'a, S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> Future
    for SignerAdapterSignOk<'a, S, P, Q>
{
    type Output = Result<Vec<u8>, MessageSignatureError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}
