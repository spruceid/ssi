use ssi_crypto::MessageSigner;

use crate::{
    InvalidVerificationMethod, Referencable, VerificationError, VerificationMethodResolutionError,
};

pub mod signer;

pub use signer::Signer;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("verification method resolution failed: {0}")]
    Resolution(#[from] VerificationMethodResolutionError),

    #[error("missing verification method")]
    MissingVerificationMethod,

    #[error("unknown verification method")]
    UnknownVerificationMethod,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error(transparent)]
    InvalidVerificationMethod(#[from] InvalidVerificationMethod),

    #[error("missing public key")]
    MissingPublicKey,

    #[error(transparent)]
    Signer(#[from] ssi_crypto::MessageSignatureError),

    #[error("invalid received signature")]
    InvalidSignature,

    #[error("invalid signature algorithm")]
    InvalidAlgorithm,

    #[error("missing signature algorithm")]
    MissingAlgorithm,
}

impl From<std::convert::Infallible> for SignatureError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

pub enum InvalidSignature {
    MissingValue,

    InvalidValue,

    MissingPublicKey,

    AmbiguousPublicKey,
}

impl From<InvalidSignature> for VerificationError {
    fn from(value: InvalidSignature) -> Self {
        match value {
            InvalidSignature::MissingValue => Self::MissingSignature,
            InvalidSignature::InvalidValue => Self::InvalidSignature,
            InvalidSignature::MissingPublicKey => Self::MissingPublicKey,
            InvalidSignature::AmbiguousPublicKey => Self::AmbiguousPublicKey,
        }
    }
}

pub trait SignatureAlgorithm<M: ?Sized + Referencable> {
    type Options: Referencable;

    type Signature: Referencable;

    /// Cryptographic signature algorithm to be used with the verification
    /// method by a remote message signer.
    type MessageSignatureAlgorithm: Copy;

    /// Signature protocol.
    type Protocol: ssi_crypto::SignatureProtocol<Self::MessageSignatureAlgorithm>;

    #[allow(async_fn_in_trait)]
    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: <Self::Options as Referencable>::Reference<'_>,
        method: M::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError>;

    fn verify<'o, 's, 'm>(
        &self,
        options: <Self::Options as Referencable>::Reference<'o>,
        signature: <Self::Signature as Referencable>::Reference<'s>,
        method: M::Reference<'m>,
        bytes: &[u8],
    ) -> Result<bool, VerificationError>;
}
