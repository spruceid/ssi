use std::ops::Deref;

use ssi_claims_core::{MessageSignatureError, SignatureError};
use ssi_crypto::algorithm::{SignatureAlgorithmInstance, SignatureAlgorithmType};

use crate::{protocol::WithProtocol, MessageSigner, SignatureProtocol, Signer, VerificationMethod};

pub struct LocalSigner<S>(pub S);

impl<M: VerificationMethod, S: Signer<M>> Signer<M> for LocalSigner<S> {
    type MessageSigner = LocalMessageSigner<S::MessageSigner>;

    async fn for_method(
        &self,
        method: std::borrow::Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(self.0.for_method(method).await?.map(LocalMessageSigner))
    }
}

impl<S> Deref for LocalSigner<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct LocalMessageSigner<S>(pub S);

impl<A: SignatureAlgorithmType, P: SignatureProtocol<A>, S: MessageSigner<A>>
    MessageSigner<WithProtocol<A, P>> for LocalMessageSigner<S>
{
    async fn sign(
        self,
        WithProtocol(algorithm_instance, protocol): WithProtocol<A::Instance, P>,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm_instance.algorithm();
        let message = protocol.prepare_message(message);
        let signature = self.0.sign(algorithm_instance, &message).await?;
        protocol.encode_signature(algorithm, signature)
    }

    async fn sign_multi(
        self,
        WithProtocol(algorithm_instance, protocol): WithProtocol<A::Instance, P>,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm_instance.algorithm();
        let messages = protocol.prepare_messages(messages);
        let signature = self.0.sign_multi(algorithm_instance, &messages).await?;
        protocol.encode_signature(algorithm, signature)
    }
}
