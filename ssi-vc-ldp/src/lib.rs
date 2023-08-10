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
pub struct DataIntegrity<T, S: CryptographicSuite> {
    /// Credential value.
    credential: T,

    /// Hashed value.
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

impl<
        V: VocabularyMut,
        I,
        M,
        T: treeldr_rust_prelude::IntoJsonLdObjectMeta<V, I, M>,
        S: CryptographicSuite,
    > treeldr_rust_prelude::IntoJsonLdObjectMeta<V, I, M> for DataIntegrity<T, S>
{
    fn into_json_ld_object_meta(
        self,
        namespace: &mut V,
        interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        self.credential
            .into_json_ld_object_meta(namespace, interpretation, meta)
    }
}
