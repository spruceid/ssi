use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_vc::Verifiable;
use ssi_verification_methods::{Referencable, SignatureError, Signer, VerificationMethodRef};
use std::{future::Future, marker::PhantomData, pin::Pin, task};

use crate::{
    suite::{CryptographicSuiteInput, GenerateProof, HashError, TransformError},
    CryptographicSuite, DataIntegrity, ProofConfiguration, UntypedProof, BuildDataIntegrity,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing credential")]
    MissingCredentialId,

    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),

    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(#[from] SignatureError),
}

impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        match value {
            crate::Error::Transform(e) => Self::Transform(e),
            crate::Error::HashFailed(e) => Self::HashFailed(e),
        }
    }
}

pub fn sign<'max, T, S: CryptographicSuite, X, I>(
    input: T,
    context: X,
    signer: &'max I,
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> SignLinkedData<'max, T, S, X, I>
where
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    I: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    DataIntegrity::<T, S>::sign(input, context, signer, suite, params)
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Sign the given credential with the given Data Integrity cryptographic
    /// suite.
    //
    // # Why is this not an `async` function?
    //
    // For some reason the Rust compiler is unable to build a future that
    // returns a value of type `Verifiable<DataIntegrity<C, S>>`.
    // See: <https://github.com/rust-lang/rust/issues/103532>
    pub fn sign<'max, X, I>(
        input: T,
        context: X,
        signer: &'max I,
        suite: S,
        params: ProofConfiguration<S::VerificationMethod, S::Options>,
    ) -> SignLinkedData<'max, T, S, X, I>
    where
        S: CryptographicSuiteInput<T, X>,
        S::VerificationMethod: 'max,
        I: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    {
        SignLinkedData {
            signer,
            build: SelfRefFuture::new(BuildBounds { suite, params }, BuildParameters { input, context }),
            inner: None
        }
    }
}

struct UnboundedBuild<T, S, X>(PhantomData<(T, S, X)>);

impl<'max, T: 'max, S: 'max + CryptographicSuiteInput<T, X>, X: 'max> UnboundedRefFuture<'max> for UnboundedBuild<T, S, X> {
    type Bound<'a> = BuildDataIntegrity<'a, T, S, X> where 'max: 'a;

    type Owned = BuildBounds<S>;

    type Output = Result<DataIntegrity<T, S>, crate::Error>;
}

struct BuildBounds<S: CryptographicSuite> {
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>
}

struct BuildParameters<T, X> {
    input: T,
    context: X,
}

impl<'max, T: 'max, S: 'max + CryptographicSuiteInput<T, X>, X: 'max> RefFutureBinder<'max, UnboundedBuild<T, S, X>> for BuildParameters<T, X> {
    fn bind<'a>(context: Self, bounds: &'a BuildBounds<S>) -> BuildDataIntegrity<'a, T, S, X>
        where
            'max: 'a {
        DataIntegrity::new(context.input, context.context, &bounds.suite, bounds.params.borrowed())
    }
}

struct UnboundedGenerateProof<S, T>(PhantomData<(S, T)>);

impl<
        'max,
        S: 'max + CryptographicSuite,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > UnboundedRefFuture<'max> for UnboundedGenerateProof<S, T>
where
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    S::Signature: 'max,
{
    type Owned = (S, S::Hashed);

    type Bound<'a> = GenerateProof<'a, S, T> where 'max: 'a;

    type Output =
        Result<UntypedProof<S::VerificationMethod, S::Options, S::Signature>, SignatureError>;
}

struct Binder<'a, S: CryptographicSuite, T> {
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
    signer: &'a T,
}

impl<
        'max,
        S: 'max + CryptographicSuite,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > RefFutureBinder<'max, UnboundedGenerateProof<S, T>> for Binder<'max, S, T>
where
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    S::Signature: 'max,
{
    fn bind<'a>(context: Self, (suite, hash): &'a (S, S::Hashed)) -> GenerateProof<'a, S, T>
    where
        'max: 'a,
    {
        suite
            .generate_proof(hash, context.signer, context.params)
    }
}

/// Future returned by the [`DataIntegrity::sign_ld`] method.
//
// # Why write the future by hand?
//
// For some reason the Rust compiler is unable to build a future that
// returns a value of type `Verifiable<DataIntegrity<C, S>>`.
// See: <https://github.com/rust-lang/rust/issues/103532>
#[pin_project]
pub struct SignLinkedData<'max, T, S, X, I>
where
    T: 'max,
    S: 'max + CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    X: 'max,
    I: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    signer: &'max I,

    #[pin]
    build: SelfRefFuture<'max, UnboundedBuild<T, S, X>>,

    #[pin]
    inner: Option<SignLinkedDataOk<'max, T, S, I>>,
}

impl<'max, T, S, X, I> Future for SignLinkedData<'max, T, S, X, I>
where
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    I: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>, // TODO find a way to hide that bound, if possible.
{
    type Output = Result<Verifiable<DataIntegrity<T, S>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let mut this = self.project();
        
        loop {
            if this.inner.is_some() {
                let inner = this.inner.as_pin_mut().unwrap();
                break inner.poll(cx)
            } else {
                match this.build.as_mut().poll(cx) {
                    task::Poll::Pending => break task::Poll::Pending,
                    task::Poll::Ready((Ok(di), BuildBounds { suite, params })) => {
                        let (input, hash) = di.into_parts();
        
                        let sign = SelfRefFuture::new(
                            (suite, hash),
                            Binder {
                                params,
                                signer: *this.signer,
                            },
                        );
        
                        this.inner.set(Some(SignLinkedDataOk {
                            payload: Some(input),
                            sign,
                        }));
                    }
                    task::Poll::Ready((Err(e), _)) => break task::Poll::Ready(Err(e.into()))
                }
            }
        }
    }
}

/// Private implementation of the `SignLinkedData` type, with the signature
/// preparation succeded.
#[pin_project]
struct SignLinkedDataOk<'max, C, S, T>
where
    S: 'max + CryptographicSuite,
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    S::Signature: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    payload: Option<C>,

    #[pin]
    sign: SelfRefFuture<'max, UnboundedGenerateProof<S, T>>,
}

impl<'max, C, S, T> Future for SignLinkedDataOk<'max, C, S, T>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>,
{
    type Output = Result<Verifiable<DataIntegrity<C, S>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();

        this.sign.poll(cx).map(|(result, (suite, hash))| {
            result
                .map(|proof| {
                    let data = this.payload.take().unwrap();
                    Verifiable::new(
                        DataIntegrity::new_hashed(data, hash),
                        proof.into_typed(suite),
                    )
                })
                .map_err(Into::into)
        })
    }
}
