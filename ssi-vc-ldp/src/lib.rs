use educe::Educe;
use linked_data::LinkedData;
use std::ops::Deref;
use suite::{HashError, TransformError};

mod decode;
mod proof;
pub mod signing;
pub mod suite;
pub mod verification;

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

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Creates a new data integrity credential from the given input data.
    ///
    /// This will transform and hash the input data using the cryptographic
    /// suite's transformation and hashing algorithms.
    pub fn new<X>(
        input: T,
        context: X,
        suite: &S,
        params: ProofConfigurationRef<S::VerificationMethod, S::Options>,
    ) -> Result<Self, Error>
    where
        S: CryptographicSuiteInput<T, X>,
    {
        let transformed = suite
            .transform(&input, context, params)
            .map_err(Error::Transform)?;

        let hashed = suite.hash(transformed, params)?;

        Ok(Self::new_hashed(input, hashed))
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
