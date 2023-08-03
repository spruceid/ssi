#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod hashes;
pub mod signatures;

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
	#[error(transparent)]
	SignatureFailed(Box<dyn 'static + std::error::Error>)
}

pub trait SignatureProtocol {
	type Output;
}

impl SignatureProtocol for () {
	type Output = Vec<u8>;
}

pub trait MessageSigner<P: SignatureProtocol> {
	fn sign(&self, message: &[u8]) -> Result<P::Output, MessageSignatureError>;
}