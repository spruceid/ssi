use linked_data::LinkedData;
use rdf_types::VocabularyMut;
use std::ops::Deref;

mod decode;
mod proof;
mod signing;
pub mod suite;
pub mod verification;

pub use proof::*;
pub use signing::*;
pub use suite::{CryptographicSuite, CryptographicSuiteInput};
pub use verification::*;

/// Data Integrity credential.
#[derive(LinkedData)]
pub struct DataIntegrity<T, S: CryptographicSuite> {
    /// Credential value.
    #[ld(flatten)]
    credential: T,

    /// Hashed value.
    #[ld(ignore)]
    hash: S::Hashed,
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    pub fn new(credential: T, hashed: S::Hashed) -> Self {
        Self {
            credential,
            hash: hashed,
        }
    }

    pub fn hashed(&self) -> &S::Hashed {
        &self.hash
    }
}

impl<T, S: CryptographicSuite> Deref for DataIntegrity<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}
