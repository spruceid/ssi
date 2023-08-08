use futures::Future;
use iref::{Iri, IriBuf};
use ssi_crypto::MessageSigner;

use crate::{VerificationError, Referencable, ReferenceOrOwnedRef};

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing verification method")]
    MissingVerificationMethod,

    #[error("unknown verification method")]
    UnknownVerificationMethod,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid verification method `{0}`")]
    InvalidVerificationMethod(IriBuf),

    #[error("missing public key")]
    MissingPublicKey,

    #[error(transparent)]
    Signer(#[from] ssi_crypto::MessageSignatureError)
}

pub enum InvalidSignature {
    MissingValue,

    InvalidValue,

    MissingPublicKey
}

impl From<InvalidSignature> for VerificationError {
    fn from(value: InvalidSignature) -> Self {
        match value {
            InvalidSignature::MissingValue => Self::MissingSignature,
            InvalidSignature::InvalidValue => Self::InvalidSignature,
            InvalidSignature::MissingPublicKey => Self::MissingPublicKey
        }
    }
}

pub trait SignatureAlgorithm<M: Referencable> {
    type Signature: Referencable;

    /// Signature protocol.
    type Protocol: ssi_crypto::SignatureProtocol;

    fn sign<S: MessageSigner<Self::Protocol>>(
        &self,
        method: M::Reference<'_>,
        bytes: &[u8],
        signer: &S
    ) -> Result<Self::Signature, SignatureError>;

    fn verify<'s, 'm>(
        &self,
        signature: <Self::Signature as Referencable>::Reference<'s>,
        method: M::Reference<'m>,
        bytes: &[u8]
    ) -> Result<bool, VerificationError>;
}

/// Verification method signer.
pub trait Signer<M: Referencable, P> {
    type Sign<'a, 'm: 'a, A: SignatureAlgorithm<M, Protocol = P>>: 'a + Future<Output = Result<A::Signature, SignatureError>> where Self: 'a, M: 'm, A::Signature: 'a;

    fn sign<'a, 'm: 'a, A: SignatureAlgorithm<M, Protocol = P>>(
        &'a self,
		algorithm: A,
        issuer: Option<Iri<'a>>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
        bytes: &'a [u8],
    ) -> Self::Sign<'a, 'm, A>
    where
        A::Signature: 'a;
}