use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_crypto::SignatureProtocol;
use std::{future::Future, marker::PhantomData, task::Poll};

use crate::{
    Cow, MethodWithSecret, Referencable, SignatureAlgorithm, SignatureError, Signer, SigningMethod,
    VerificationMethodResolver,
};

/// Simple signer implementation that always uses the given secret to sign
/// every message.
///
/// This type is useful for quick testing but should not be used in real
/// applications since the secret used to sign messages will realistically not
/// match the verification method used to verify the signature.
pub struct SingleSecretSigner<R, S> {
    resolver: R,
    secret: S,
}

impl<R, S> SingleSecretSigner<R, S> {
    /// Creates a new signer with the given verification method resolver and
    /// secret.
    pub fn new(resolver: R, secret: S) -> Self {
        Self { resolver, secret }
    }
}

impl<M: Referencable, P: SignatureProtocol, V, S> Signer<M, P> for SingleSecretSigner<V, S>
where
    M: SigningMethod<S>,
    V: VerificationMethodResolver<M>,
{
    type Sign<'a, A: crate::SignatureAlgorithm<M, Protocol = P>> = Sign<'a, M, V, A, S> where Self: 'a, M: 'a, A: 'a, A::Signature: 'a;

    fn sign<'a, 'o: 'a, 'm: 'a, A: crate::SignatureAlgorithm<M, Protocol = P>>(
        &'a self,
        algorithm: A,
        options: <A::Options as Referencable>::Reference<'o>,
        issuer: Option<&'a iref::Iri>,
        method: Option<crate::ReferenceOrOwnedRef<'m, M>>,
        bytes: &'a [u8],
    ) -> Self::Sign<'a, A>
    where
        A: 'a,
        A::Signature: 'a,
    {
        match method {
            Some(_) => Sign::Ok(ResolveAndSign {
                resolve: self.resolver.resolve_verification_method(issuer, method),
                algorithm: Some(algorithm),
                options: <A::Options as Referencable>::apply_covariance(options),
                bytes,
                secret: &self.secret,
                sign: None,
            }),
            None => Sign::Err(Some(SignatureError::MissingVerificationMethod)),
        }
    }
}

#[pin_project(project = SignProj)]
pub enum Sign<'a, M: 'a + Referencable, V: 'a + VerificationMethodResolver<M>, A, S>
where
    M: 'a + Referencable + SigningMethod<S>,
    V: 'a + VerificationMethodResolver<M>,
    A: 'a + SignatureAlgorithm<M>,
    S: 'a,
{
    Err(Option<SignatureError>),
    Ok(#[pin] ResolveAndSign<'a, M, V, A, S>),
}

impl<'a, M, V, A, S> Future for Sign<'a, M, V, A, S>
where
    M: 'a + Referencable + SigningMethod<S>,
    V: 'a + VerificationMethodResolver<M>,
    A: 'a + SignatureAlgorithm<M>,
    S: 'a,
{
    type Output = Result<A::Signature, SignatureError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project() {
            SignProj::Ok(f) => f.poll(cx),
            SignProj::Err(e) => std::task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

#[pin_project]
pub struct ResolveAndSign<'a, M, V, A, S>
where
    M: 'a + Referencable + SigningMethod<S>,
    V: 'a + VerificationMethodResolver<M>,
    A: 'a + SignatureAlgorithm<M>,
    S: 'a,
{
    #[pin]
    resolve: V::ResolveVerificationMethod<'a>,
    algorithm: Option<A>,
    options: <A::Options as Referencable>::Reference<'a>,
    bytes: &'a [u8],
    secret: &'a S,

    #[pin]
    sign: Option<SelfRefFuture<'a, UnboundSignWithMethodAndSecret<'a, M, A, S>>>,
}

impl<'a, M, V, A, S> Future for ResolveAndSign<'a, M, V, A, S>
where
    M: 'a + Referencable + SigningMethod<S>,
    V: 'a + VerificationMethodResolver<M>,
    A: SignatureAlgorithm<M>,
    S: 'a,
{
    type Output = Result<A::Signature, SignatureError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut this = self.project();

        if this.sign.is_none() {
            match this.resolve.poll(cx) {
                Poll::Ready(Ok(method)) => this.sign.set(Some(SelfRefFuture::new(
                    Owned::<M, A> {
                        algorithm: this.algorithm.take().unwrap(),
                        method,
                    },
                    Binder::<A::Options, S> {
                        options: *this.options,
                        bytes: this.bytes,
                        secret: *this.secret,
                    },
                ))),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            }
        }

        let sign = Option::as_pin_mut(this.sign).unwrap();
        sign.poll(cx).map(|(r, _)| r)
    }
}

struct UnboundSignWithMethodAndSecret<'a, M, A, S>(PhantomData<(&'a (), M, A, S)>);

impl<'a, M, A, S> UnboundedRefFuture<'a> for UnboundSignWithMethodAndSecret<'a, M, A, S>
where
    M: 'a + Referencable + SigningMethod<S>,
    A: 'a + SignatureAlgorithm<M>,
    S: 'a,
{
    type Bound<'m> = A::Sign<'m, MethodWithSecret<'m, 'a, M, S>> where 'a: 'm;

    type Owned = Owned<'a, M, A>;

    type Output = Result<A::Signature, SignatureError>;
}

struct Owned<'a, M: 'a + Referencable, A> {
    algorithm: A,
    method: Cow<'a, M>,
}

struct Binder<'a, O: 'a + Referencable, S> {
    options: O::Reference<'a>,
    bytes: &'a [u8],
    secret: &'a S,
}

impl<'a, M, A, S> RefFutureBinder<'a, UnboundSignWithMethodAndSecret<'a, M, A, S>>
    for Binder<'a, A::Options, S>
where
    M: 'a + Referencable + SigningMethod<S>,
    A: 'a + SignatureAlgorithm<M>,
    S: 'a,
{
    fn bind<'m>(
        context: Self,
        value: &'m Owned<'a, M, A>,
    ) -> A::Sign<'m, MethodWithSecret<'m, 'a, M, S>>
    where
        'a: 'm,
    {
        value.algorithm.sign(
            <A::Options as Referencable>::apply_covariance(context.options),
            value.method.as_reference(),
            context.bytes,
            MethodWithSecret::new(value.method.as_reference(), context.secret),
        )
    }
}
