use crate::AlgorithmInstance;

pub mod symmetric;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "secp256k1")]
pub mod k256;

#[cfg(feature = "secp256r1")]
pub mod p256;

#[cfg(feature = "secp384r1")]
pub mod p384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyType {
    Symmetric,
    Rsa,
    Ed25519,
    K256,
    P256,
    P384,
}

impl KeyType {
    pub fn default_algorithm_params(&self) -> Option<AlgorithmInstance> {
        match self {
            Self::Symmetric => Some(AlgorithmInstance::HS512),
            Self::Rsa => Some(AlgorithmInstance::RS256),
            Self::Ed25519 => Some(AlgorithmInstance::EdDsa),
            Self::K256 => Some(AlgorithmInstance::ES256K),
            Self::P256 => Some(AlgorithmInstance::ES256),
            Self::P384 => Some(AlgorithmInstance::ES384),
        }
    }
}
