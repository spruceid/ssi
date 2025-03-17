use ssi_claims_core::Parameters;
use ssi_crypto::Error;

use crate::{CryptographicSuite, DataIntegrity, ProofRef};

/// Cryptographic suite with selective disclosure capabilities.
pub trait SelectiveCryptographicSuite: CryptographicSuite {
    /// Options specifying what claims to select and how.
    type SelectionOptions;
}

/// Cryptographic suite with selective disclosure capabilities on a given type
/// `T`.
///
/// Provides the `select` method on the cryptosuite.
pub trait CryptographicSuiteSelect<T>: SelectiveCryptographicSuite {
    /// Select a subset of claims to disclose.
    #[allow(async_fn_in_trait)]
    async fn select(
        &self,
        unsecured_document: &T,
        proof: ProofRef<'_, Self>,
        options: Self::SelectionOptions,
        params: &Parameters,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, Self>, Error>;
}
