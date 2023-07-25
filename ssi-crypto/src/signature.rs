use crate::verification::VerificationMethod;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("unknown verification method")]
    UnknownVerificationMethod,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    /// The verification method used to sign the key is invalid.
    #[error("invalid verification method")]
    InvalidVerificationMethod,
}

pub trait Signer<M: VerificationMethod> {
    fn sign(&self, method: &M, bytes: &[u8]) -> Result<M::Signature, SignatureError>;
}
