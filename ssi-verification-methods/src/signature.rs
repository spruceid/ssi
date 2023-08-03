// pub mod any;
// mod jws;
// mod jws_public_key_jwk;
// pub mod base58_public_key_jwk_or_multibase;
// mod multibase;
// mod signature_value;
// mod eip712;

// pub use any::{Any, AnyRef};
// pub use jws::*;
// pub use jws_public_key_jwk::*;
// pub use base58_public_key_jwk_or_multibase::{Base58PublicKeyJwkOrMultibase, Base58PublicKeyJwkOrMultibaseRef};
// pub use self::multibase::*;
// pub use signature_value::*;
// pub use eip712::{Eip712Signature, Eip712SignatureRef};

use ssi_crypto::MessageSigner;

use crate::VerificationError;

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

    #[error(transparent)]
    Signer(#[from] ssi_crypto::MessageSignatureError)
}

pub trait SignatureAlgorithm<M> {
    type Signature;

    /// Signature protocol.
    type Protocol: ssi_crypto::SignatureProtocol;

    fn sign<S: MessageSigner<Self::Protocol>>(
        &self,
        method: &M,
        bytes: &[u8],
        signer: &S
    ) -> Result<Self::Signature, SignatureError>;

    fn verify(&self,
        signature: &Self::Signature,
        method: &M,
        bytes: &[u8]
    ) -> Result<bool, VerificationError>;
}

/// Verification method signer.
pub trait Signer<M, P> {
    fn sign<A: SignatureAlgorithm<M, Protocol = P>>(
        &self,
		algorithm: A,
        method: &M,
        bytes: &[u8],
    ) -> Result<A::Signature, SignatureError>;
}