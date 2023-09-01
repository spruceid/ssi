use futures::Future;
use iref::{Iri, IriBuf};
use ssi_crypto::{MessageSigner, SignatureProtocol};

use crate::{
    InvalidVerificationMethod, Referencable, ReferenceOrOwnedRef, VerificationError,
    VerificationMethodResolutionError,
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
}

pub enum InvalidSignature {
    MissingValue,

    InvalidValue,

    MissingPublicKey,
}

impl From<InvalidSignature> for VerificationError {
    fn from(value: InvalidSignature) -> Self {
        match value {
            InvalidSignature::MissingValue => Self::MissingSignature,
            InvalidSignature::InvalidValue => Self::InvalidSignature,
            InvalidSignature::MissingPublicKey => Self::MissingPublicKey,
        }
    }
}

pub trait SignatureAlgorithm<M: ?Sized + Referencable> {
    type Signature: Referencable;

    /// Signature protocol.
    type Protocol: ssi_crypto::SignatureProtocol;

    /// Future returned by the `sign` method.
    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>>: 'a
        + Future<Output = Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        method: M::Reference<'_>,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S>
    where
        <Self::Protocol as SignatureProtocol>::Output: 'a;

    fn verify<'s, 'm>(
        &self,
        signature: <Self::Signature as Referencable>::Reference<'s>,
        method: M::Reference<'m>,
        bytes: &[u8],
    ) -> Result<bool, VerificationError>;
}
