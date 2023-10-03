use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_vc::Verifiable;
use ssi_verification_methods::{Referencable, SignatureError, Signer, VerificationMethodRef};
use std::{future::Future, marker::PhantomData, pin::Pin, task};

use crate::{
    suite::{CryptographicSuiteInput, GenerateProof, HashError, TransformError},
    CryptographicSuite, DataIntegrity, ProofConfiguration, UntypedProof,
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

pub fn sign<'max, C, S: CryptographicSuite, X, T>(
    input: C,
    context: X,
    signer: &'max T,
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> SignLinkedData<'max, C, S, T>
where
    S: CryptographicSuiteInput<C, X>,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    DataIntegrity::<C, S>::sign(input, context, signer, suite, params)
}

impl<C, S: CryptographicSuite> DataIntegrity<C, S> {
    /// Sign the given credential with the given Data Integrity cryptographic
    /// suite.
    //
    // # Why is this not an `async` function?
    //
    // For some reason the Rust compiler is unable to build a future that
    // returns a value of type `Verifiable<DataIntegrity<C, S>>`.
    // See: <https://github.com/rust-lang/rust/issues/103532>
    pub fn sign<'max, X, T>(
        input: C,
        context: X,
        signer: &'max T,
        suite: S,
        params: ProofConfiguration<S::VerificationMethod, S::Options>,
    ) -> SignLinkedData<'max, C, S, T>
    where
        S: CryptographicSuiteInput<C, X>,
        S::VerificationMethod: 'max,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    {
        let inner = match Self::new(input, context, &suite, params.borrowed()) {
            Ok(di) => {
                let (input, hash) = di.into_parts();

                let sign = SelfRefFuture::new(
                    hash,
                    Binder {
                        suite: &suite,
                        params,
                        signer,
                    },
                );

                SignLinkedDataInner::Ok(SignLinkedDataOk {
                    payload: Some((input, suite)),
                    sign,
                })
            }
            Err(e) => SignLinkedDataInner::Err(Some(e.into())),
        };

        SignLinkedData { inner }
    }
}

struct UnboundedGenerateProof<S, T>(PhantomData<(S, T)>);

impl<
        'max,
        S: CryptographicSuite,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > UnboundedRefFuture<'max> for UnboundedGenerateProof<S, T>
where
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    S::Signature: 'max,
{
    type Owned = S::Hashed;

    type Bound<'a> = GenerateProof<'a, S, T> where 'max: 'a;

    type Output =
        Result<UntypedProof<S::VerificationMethod, S::Options, S::Signature>, SignatureError>;
}

struct Binder<'s, 'a, S: CryptographicSuite, T> {
    suite: &'s S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
    signer: &'a T,
}

impl<
        's,
        'max,
        S: CryptographicSuite,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > RefFutureBinder<'max, UnboundedGenerateProof<S, T>> for Binder<'s, 'max, S, T>
where
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    S::Signature: 'max,
{
    fn bind<'a>(context: Self, hash: &'a S::Hashed) -> GenerateProof<'a, S, T>
    where
        'max: 'a,
    {
        context
            .suite
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
pub struct SignLinkedData<'max, C, S, T>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    #[pin]
    inner: SignLinkedDataInner<'max, C, S, T>,
}

impl<'max, C, S, T> Future for SignLinkedData<'max, C, S, T>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>, // TODO find a way to hide that bound, if possible.
{
    type Output = Result<Verifiable<DataIntegrity<C, S>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}

/// Private implementation of the `SignLinkedData` type.
#[pin_project(project = SignLinkedDataInnerProj)]
enum SignLinkedDataInner<'max, C, S, T>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    Err(Option<Error>),
    Ok(#[pin] SignLinkedDataOk<'max, C, S, T>),
}

impl<'max, C, S, T> Future for SignLinkedDataInner<'max, C, S, T>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>,
{
    type Output = Result<Verifiable<DataIntegrity<C, S>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            SignLinkedDataInnerProj::Ok(f) => f.poll(cx),
            SignLinkedDataInnerProj::Err(e) => task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

/// Private implementation of the `SignLinkedData` type, with the signature
/// preparation succeded.
#[pin_project]
struct SignLinkedDataOk<'max, C, S, T>
where
    S: CryptographicSuite,
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::SignatureAlgorithm: 'max,
    S::Options: 'max,
    S::Signature: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    payload: Option<(C, S)>,

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

        this.sign.poll(cx).map(|(result, hash)| {
            result
                .map(|proof| {
                    let (data, suite) = this.payload.take().unwrap();
                    Verifiable::new(
                        DataIntegrity::new_hashed(data, hash),
                        proof.into_typed(suite),
                    )
                })
                .map_err(Into::into)
        })
    }
}
