#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod hashes;
pub mod signatures;
pub mod protocol;

use std::marker::PhantomData;

pub use protocol::SignatureProtocol;

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
	#[error(transparent)]
	SignatureFailed(Box<dyn 'static + std::error::Error>),

	#[error("invalid signature client query")]
	InvalidQuery,

	#[error("invalid signer response")]
	InvalidResponse
}

impl MessageSignatureError {
	pub fn signature_failed<E: 'static + std::error::Error>(e: E) -> Self {
		Self::SignatureFailed(Box::new(e))
	}
}

pub trait MessageSigner<P: SignatureProtocol> {
	fn sign(
		&self,
		protocol: P,
		message: &[u8]
	) -> Result<P::Output, MessageSignatureError>;
}

pub struct ProjectedMessageSigner<'a, S, P> {
    // Underlying signer.
    signer: &'a S,

    protocol: PhantomData<P>
}

impl<'a, S, P> ProjectedMessageSigner<'a, S, P> {
	pub fn new(signer: &'a S) -> Self {
		Self {
			signer,
			protocol: PhantomData
		}
	}
}

impl<'a, S: MessageSigner<P>, P: SignatureProtocol, Q: SignatureProtocol> MessageSigner<Q> for ProjectedMessageSigner<'a, S, P>
where
    P: TryFrom<Q>,
    Q::Output: TryFrom<P::Output>
{
    fn sign(
        &self,
        protocol: Q,
        message: &[u8]
    ) -> Result<Q::Output, MessageSignatureError> {
        self.signer.sign(protocol.try_into().map_err(|_| MessageSignatureError::InvalidQuery)?, message)?.try_into().map_err(|_| MessageSignatureError::InvalidResponse)
    }
}