use std::{borrow::Cow, sync::Arc};

use ssi_claims_core::SignatureError;

use crate::{local::LocalSigner, MethodWithSecret, Signer, VerificationMethod};

/// Simple signer implementation that always uses the given secret to sign
/// every message.
///
/// This type is useful for quick testing but should not be used in real
/// applications since the secret used to sign messages will realistically not
/// match the verification method used to verify the signature.
pub struct SingleSecretSigner<S> {
    secret: Arc<S>,
}

impl<S> SingleSecretSigner<S> {
    /// Creates a new signer with the given secret.
    pub fn new(secret: S) -> Self {
        Self {
            secret: Arc::new(secret),
        }
    }

    pub fn secret(&self) -> &S {
        &self.secret
    }

    pub fn into_local(self) -> LocalSigner<Self> {
        LocalSigner(self)
    }
}

impl<M: VerificationMethod, S> Signer<M> for SingleSecretSigner<S> {
    type MessageSigner = MethodWithSecret<M, S>;

    async fn for_method(
        &self,
        method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(Some(MethodWithSecret::new(
            method.into_owned(),
            self.secret.clone(),
        )))
    }
}
