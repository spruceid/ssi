use core::fmt;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing signature algorithm")]
    MissingAlgorithm,

	#[error("algorithm mismatch")]
	AlgorithmMismatch,

	#[error("unsupported algorithm")]
	UnsupportedAlgorithm,

	#[error("{0}")]
	Other(String)
}

impl SignatureError {
	pub fn other(e: impl fmt::Display) -> Self {
		Self::Other(e.to_string())
	}
}