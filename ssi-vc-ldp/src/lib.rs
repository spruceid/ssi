use educe::Educe;
use linked_data::LinkedData;
use pin_project::pin_project;
use ssi_core::futures::{UnboundedRefFuture, RefFutureBinder, SelfRefFuture};
use std::marker::PhantomData;
use std::ops::Deref;
use std::{future::Future, task, pin::Pin};
use suite::{HashError, TransformError};

mod decode;
mod proof;
pub mod signing;
pub mod suite;
pub mod verification;
pub mod eip712;

pub use proof::*;
pub use signing::sign;
pub use suite::{CryptographicSuite, CryptographicSuiteInput, LinkedDataInput};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),
}

/// Data Integrity credential.
#[derive(Educe, serde::Serialize, LinkedData)]
#[educe(Clone(bound = "T: Clone, S::Hashed: Clone"))]
#[serde(transparent)]
pub struct DataIntegrity<T, S: CryptographicSuite> {
    /// Credential value.
    #[ld(flatten)]
    credential: T,

    /// Hashed value.
    #[serde(skip)]
    #[ld(ignore)]
    hash: S::Hashed,
}

#[pin_project]
pub struct BuildDataIntegrity<'a, T: 'a, S: 'a + CryptographicSuiteInput<T, X>, X: 'a> {
    suite: &'a S,

    params: ProofConfigurationRef<'a, S::VerificationMethod, S::Options>,

    #[pin]
    transform: SelfRefFuture<'a, UnboundedTransform<T, X, S>>
}

impl<'a, T: 'a, S: 'a + CryptographicSuiteInput<T, X>, X: 'a> Future for BuildDataIntegrity<'a, T, S, X> {
    type Output = Result<DataIntegrity<T, S>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        match this.transform.poll(cx) {
            task::Poll::Pending => task::Poll::Pending,
            task::Poll::Ready((Err(e), _)) => task::Poll::Ready(Err(Error::Transform(e))),
            task::Poll::Ready((Ok(transformed), input)) => {
                match this.suite.hash(transformed, *this.params) {
                    Err(e) => task::Poll::Ready(Err(Error::HashFailed(e))),
                    Ok(hashed) => task::Poll::Ready(Ok(DataIntegrity::new_hashed(
                        input,
                        hashed
                    )))
                }
            }
        }
    }
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Creates a new data integrity credential from the given input data.
    ///
    /// This will transform and hash the input data using the cryptographic
    /// suite's transformation and hashing algorithms.
    pub fn new<'a, 'c: 'a, X: 'a>(
        input: T,
        context: X,
        suite: &'a S,
        params: ProofConfigurationRef<'c, S::VerificationMethod, S::Options>,
    ) -> BuildDataIntegrity<'a, T, S, X>
    where
        T: 'a,
        S: CryptographicSuiteInput<T, X>,
    {
        let params = params.shorten_lifetime();
        BuildDataIntegrity {
            suite,
            params,
            // input: Some(input),
            transform: SelfRefFuture::new(input, TransformParameters {
                suite,
                context,
                params
            })
        }
    }

    pub fn new_hashed(credential: T, hashed: S::Hashed) -> Self {
        Self {
            credential,
            hash: hashed,
        }
    }

    pub fn value(&self) -> &T {
        &self.credential
    }

    pub fn hashed(&self) -> &S::Hashed {
        &self.hash
    }

    pub fn into_parts(self) -> (T, S::Hashed) {
        (self.credential, self.hash)
    }
}

impl<T, S: CryptographicSuite> Deref for DataIntegrity<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}

struct UnboundedTransform<T, X, S>(PhantomData<(T, X, S)>);

impl<'max, T: 'max, X: 'max, S: 'max + CryptographicSuiteInput<T, X>> UnboundedRefFuture<'max> for UnboundedTransform<T, X, S> {
    type Bound<'a> = S::Transform<'a> where 'max: 'a;

    type Owned = T;

    type Output = Result<S::Transformed, TransformError>;
}

struct TransformParameters<'a, X, S: CryptographicSuite> {
    suite: &'a S,
    context: X,
    params: ProofConfigurationRef<'a, S::VerificationMethod, S::Options>,
}

impl<'max, T: 'max, X: 'max, S: 'max + CryptographicSuiteInput<T, X>> RefFutureBinder<'max, UnboundedTransform<T, X, S>> for TransformParameters<'max, X, S> {
    fn bind<'a>(context: Self, value: &'a T) -> S::Transform<'a>
        where
            'max: 'a {
        context.suite.transform(value, context.context, context.params)
    }
}