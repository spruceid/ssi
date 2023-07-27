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

    #[error("missing public key")]
    MissingPublicKey,
}

pub trait Signer<M: VerificationMethod> {
    fn sign(
        &self,
        context: M::Context<'_>,
        method: &M,
        bytes: &[u8],
    ) -> Result<M::Signature, SignatureError>;
}
