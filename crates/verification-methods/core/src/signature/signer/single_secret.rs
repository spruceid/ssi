use crate::{MethodWithSecret, Referencable, SignatureProtocol, Signer, SigningMethod};

/// Simple signer implementation that always uses the given secret to sign
/// every message.
///
/// This type is useful for quick testing but should not be used in real
/// applications since the secret used to sign messages will realistically not
/// match the verification method used to verify the signature.
pub struct SingleSecretSigner<S> {
    secret: S,
}

impl<S> SingleSecretSigner<S> {
    /// Creates a new signer with the given secret.
    pub fn new(secret: S) -> Self {
        Self { secret }
    }

    pub fn secret(&self) -> &S {
        &self.secret
    }
}

impl<M: Referencable, A: Copy, P: Copy + SignatureProtocol<A>, S> Signer<M, A, P>
    for SingleSecretSigner<S>
where
    M: SigningMethod<S, A>,
{
    type MessageSigner<'a> = MethodWithSecret<'a, 'a, M, S> where Self: 'a, M: 'a;

    async fn for_method<'a>(&'a self, method: M::Reference<'a>) -> Option<Self::MessageSigner<'a>> {
        Some(MethodWithSecret::new(method, &self.secret))
    }
}
