use std::borrow::Cow;

use crate::AlgorithmInstance;

pub mod symmetric;
pub use symmetric::SymmetricKey;

#[cfg(feature = "rsa")]
pub mod rsa;
#[cfg(feature = "rsa")]
pub use rsa::{RsaPublicKey, RsaSecretKey};

pub mod ecdsa;
pub use ecdsa::{EcdsaKeyType, EcdsaPublicKey, EcdsaSecretKey};

pub mod eddsa;
pub use eddsa::{EdDsaKeyType, EdDsaPublicKey, EdDsaSecretKey};

/// Key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyType {
    Symmetric(usize),
    Rsa(usize),
    Ecdsa(EcdsaKeyType),
    EdDsa(EdDsaKeyType),
}

impl KeyType {
    pub fn name(&self) -> Cow<'static, str> {
        match self {
            Self::Symmetric(n) => Cow::Owned(format!("SYM-{n}")),
            Self::Rsa(1024) => Cow::Borrowed("RSA-1024"),
            Self::Rsa(2048) => Cow::Borrowed("RSA-2048"),
            Self::Rsa(3072) => Cow::Borrowed("RSA-3072"),
            Self::Rsa(4096) => Cow::Borrowed("RSA-4096"),
            Self::Rsa(n) => Cow::Owned(format!("RSA-{n}")),
            Self::Ecdsa(t) => Cow::Borrowed(t.name()),
            Self::EdDsa(t) => Cow::Borrowed(t.name()),
        }
    }

    pub fn default_algorithm_params(&self) -> Option<AlgorithmInstance> {
        match self {
            Self::Symmetric(_) => Some(AlgorithmInstance::HS512),
            Self::Rsa(_) => Some(AlgorithmInstance::RS256),
            Self::EdDsa(t) => Some(t.default_algorithm_params()),
            Self::Ecdsa(t) => Some(t.default_algorithm_params()),
        }
    }
}
