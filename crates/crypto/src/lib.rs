use key::KeyConversionError;

#[cfg(feature = "ed25519")]
pub use ed25519_dalek as ed25519;
#[cfg(feature = "secp256k1")]
pub use k256;
#[cfg(feature = "secp256r1")]
pub use p256;
#[cfg(feature = "secp384r1")]
pub use p384;
pub use rand;
#[cfg(feature = "rsa")]
pub use rsa;
pub use sha2;
pub use sha3;

pub mod algorithm;
pub mod hash;
pub mod key;
mod options;
mod recovery;
pub mod signature;
mod utils;
mod verification;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
pub use hash::HashFunction;
pub use key::{KeyType, PublicKey, SecretKey};
pub use options::*;
pub use recovery::*;
pub use signature::{Issuer, Signer, SigningKey};
pub use utils::*;
pub use verification::*;

/// Signature or verification error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input")]
    InputMalformed(anyhow::Error),

    #[error("verifying key not found")]
    KeyNotFound(Option<Vec<u8>>),

    #[error("key conversion failed: {0}")]
    KeyConversion(#[from] KeyConversionError),

    #[error("invalid key")]
    KeyInvalid,

    #[error("unsupported key")]
    KeyUnsupported,

    #[error("invalid key use")]
    KeyInvalidUse,

    #[error("key controller not found")]
    KeyControllerNotFound,

    #[error("invalid key controller")]
    KeyControllerInvalid,

    #[error("unsupported key controller")]
    KeyControllerUnsupported,

    #[error("missing algorithm")]
    AlgorithmMissing,

    #[error("unsupported algorithm `{0}`")]
    AlgorithmUnsupported(Algorithm),

    #[error("missing signature")]
    SignatureMissing,

    #[error("malformed signature")]
    SignatureMalformed,

    #[error("too many signature")]
    SignatureTooMany,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl Error {
    pub fn internal(e: impl Into<anyhow::Error>) -> Self {
        Self::Internal(e.into())
    }

    pub fn malformed_input(e: impl Into<anyhow::Error>) -> Self {
        Self::InputMalformed(e.into())
    }
}
