use ssi_crypto::VerificationError;

mod any;
mod public_key_jwk;

pub use any::*;
pub use public_key_jwk::*;

/// Verification method context error.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// The verification method requires the cryptographic suite to provide the
    /// public key, but it is missing.
    #[error("missing public key")]
    MissingPublicKey,
}

impl From<ContextError> for VerificationError {
    fn from(value: ContextError) -> Self {
        match value {
            ContextError::MissingPublicKey => Self::MissingPublicKey,
        }
    }
}

/// Empty context, used by most verification methods.
pub type NoContext = ();
