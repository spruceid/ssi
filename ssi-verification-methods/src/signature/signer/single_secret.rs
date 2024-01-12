use ssi_crypto::SignatureProtocol;

use crate::{
    MethodWithSecret, Referencable, SignatureError, Signer, SigningMethod,
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

impl<M: Referencable, B: Copy, P: SignatureProtocol<B>, V, S> Signer<M, B, P>
    for SingleSecretSigner<V, S>
where
    M: SigningMethod<S, B>,
    V: VerificationMethodResolver<M>,
{
    async fn sign<
        'a,
        'o: 'a,
        'm: 'a,
        A: crate::SignatureAlgorithm<M, MessageSignatureAlgorithm = B, Protocol = P>,
    >(
        &'a self,
        algorithm: A,
        options: <A::Options as Referencable>::Reference<'o>,
        issuer: Option<&'a iref::Iri>,
        method: Option<crate::ReferenceOrOwnedRef<'m, M>>,
        bytes: &'a [u8],
    ) -> Result<A::Signature, SignatureError>
    where
        A: 'a,
        A::Signature: 'a,
    {
        match method {
            Some(m) => {
                let method = self
                    .resolver
                    .resolve_verification_method(issuer, Some(m))
                    .await?;
                let method = method.as_reference();
                algorithm
                    .sign(
                        <A::Options as Referencable>::apply_covariance(options),
                        method,
                        bytes,
                        MethodWithSecret::<M, _>::new(method, &self.secret),
                    )
                    .await
            }
            None => Err(SignatureError::MissingVerificationMethod),
        }
    }
}
