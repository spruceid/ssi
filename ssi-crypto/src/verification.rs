use crate::{Algorithm, UnsupportedAlgorithm};

/// Verifier.
pub trait Verifier {
    /// Verify the given `signed_bytes`, signed using the given `algorithm`,
    /// against the input `unsigned_bytes`.
    fn verify(
        &self,
        algorithm: Algorithm,
        unsigned_bytes: &[u8],
        signed_bytes: &[u8],
    ) -> Result<bool, UnsupportedAlgorithm>;
}

/// Verifier provider.
///
/// For instance, for Data Integrity VCs,
/// the implementor is in charge of retrieve verification methods as described
/// in <https://w3c.github.io/vc-data-integrity/#retrieve-verification-method>.
pub trait VerifierProvider<M> {
    /// Verifier type.
    type Verifier<'a>: Verifier
    where
        Self: 'a;

    /// Retrieve the verifier identified by the given verification `method`.
    fn get_verifier(&self, method: &M) -> Option<Self::Verifier<'_>>;
}
