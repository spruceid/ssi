use crate::{
    ControllerProvider, ProofPurpose, Referencable, ReferenceOrOwnedRef, SignatureAlgorithm,
    VerificationError, VerificationMethod, VerificationMethodResolver,
};
use iref::Iri;

/// Verifier.
pub trait Verifier<M: Referencable>: VerificationMethodResolver<M> + ControllerProvider {
    /// Verify the given `signature`, signed using the given `algorithm`,
    /// against the input `signing`.
    #[allow(async_fn_in_trait)]
    #[allow(clippy::too_many_arguments)]
    async fn verify<'f, 'o: 'f, 'm: 'f, 's: 'f, A: SignatureAlgorithm<M>>(
        &'f self,
        algorithm: A,
        options: <A::Options as Referencable>::Reference<'o>,
        issuer: Option<&'f Iri>,
        method_reference: Option<ReferenceOrOwnedRef<'m, M>>,
        proof_purpose: ProofPurpose,
        signing_bytes: &'f [u8],
        signature: <A::Signature as Referencable>::Reference<'s>,
    ) -> Result<bool, VerificationError>
    where
        M: 'f + VerificationMethod,
    {
        let method = self
            .resolve_verification_method(issuer, method_reference)
            .await?;
        if let Some(controller_id) = method.controller() {
            self.ensure_allows_verification_method(controller_id, method.id(), proof_purpose)
                .await?;
        }
        algorithm.verify(options, signature, method.as_reference(), signing_bytes)
    }
}

impl<M: Referencable, T: VerificationMethodResolver<M> + ControllerProvider> Verifier<M> for T {}
