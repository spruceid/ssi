//! Legacy types and traits, soon to be removed.
use core::fmt;

use super::{
    Algorithm, AlgorithmInstance, Es256K, Es256KR, EsKeccakK, EsKeccakKR, UnsupportedAlgorithm,
};

pub trait SignatureAlgorithmType {
    type Instance: SignatureAlgorithmInstance<Algorithm = Self>;
}

pub trait SignatureAlgorithmInstance {
    type Algorithm;

    fn algorithm(&self) -> Self::Algorithm;
}

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyES256K {
    /// ECDSA using secp256k1 (K-256) and SHA-256, without recovery bit.
    ES256K,

    /// ECDSA using secp256k1 (K-256) and SHA-256, with recovery bit.
    ES256KR,
}

impl SignatureAlgorithmType for AnyES256K {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyES256K {
    type Algorithm = AnyES256K;

    fn algorithm(&self) -> AnyES256K {
        *self
    }
}

impl TryFrom<Algorithm> for AnyES256K {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::Es256K => Ok(Self::ES256K),
            Algorithm::Es256KR => Ok(Self::ES256KR),
            other => Err(UnsupportedAlgorithm(other)),
        }
    }
}

impl From<AnyES256K> for Algorithm {
    fn from(value: AnyES256K) -> Self {
        match value {
            AnyES256K::ES256K => Self::Es256K,
            AnyES256K::ES256KR => Self::Es256KR,
        }
    }
}

impl From<Es256K> for AnyES256K {
    fn from(_value: Es256K) -> Self {
        Self::ES256K
    }
}

impl From<Es256KR> for AnyES256K {
    fn from(_value: Es256KR) -> Self {
        Self::ES256KR
    }
}

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyESKeccakK {
    /// ECDSA using secp256k1 (K-256) and Keccak-256.
    ///
    /// Like `ES256K` but using Keccak-256 instead of SHA-256.
    ESKeccakK,

    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    ///
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR,
}

impl SignatureAlgorithmType for AnyESKeccakK {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyESKeccakK {
    type Algorithm = AnyESKeccakK;

    fn algorithm(&self) -> AnyESKeccakK {
        *self
    }
}

impl TryFrom<Algorithm> for AnyESKeccakK {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::EsKeccakK => Ok(Self::ESKeccakK),
            Algorithm::EsKeccakKR => Ok(Self::ESKeccakKR),
            other => Err(UnsupportedAlgorithm(other)),
        }
    }
}

impl From<AnyESKeccakK> for Algorithm {
    fn from(value: AnyESKeccakK) -> Self {
        match value {
            AnyESKeccakK::ESKeccakK => Self::EsKeccakK,
            AnyESKeccakK::ESKeccakKR => Self::EsKeccakKR,
        }
    }
}

impl From<AnyESKeccakK> for AlgorithmInstance {
    fn from(value: AnyESKeccakK) -> Self {
        match value {
            AnyESKeccakK::ESKeccakK => Self::EsKeccakK,
            AnyESKeccakK::ESKeccakKR => Self::EsKeccakKR,
        }
    }
}

impl From<EsKeccakK> for AnyESKeccakK {
    fn from(_value: EsKeccakK) -> Self {
        Self::ESKeccakK
    }
}

impl From<EsKeccakKR> for AnyESKeccakK {
    fn from(_value: EsKeccakKR) -> Self {
        Self::ESKeccakKR
    }
}

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyES {
    /// ECDSA using secp256k1 (K-256) and SHA-256, without recovery bit.
    ES256K,

    /// ECDSA using secp256k1 (K-256) and SHA-256, with recovery bit.
    ES256KR,

    ESKeccakK,

    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    ///
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR,
}

impl SignatureAlgorithmType for AnyES {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyES {
    type Algorithm = AnyES;

    fn algorithm(&self) -> AnyES {
        *self
    }
}

impl TryFrom<Algorithm> for AnyES {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::Es256K => Ok(Self::ES256K),
            Algorithm::Es256KR => Ok(Self::ES256KR),
            other => Err(UnsupportedAlgorithm(other)),
        }
    }
}

impl From<AnyES> for Algorithm {
    fn from(value: AnyES) -> Self {
        match value {
            AnyES::ES256K => Self::Es256K,
            AnyES::ES256KR => Self::Es256KR,
            AnyES::ESKeccakK => Self::EsKeccakK,
            AnyES::ESKeccakKR => Self::EsKeccakKR,
        }
    }
}

impl From<Es256K> for AnyES {
    fn from(_value: Es256K) -> Self {
        Self::ES256K
    }
}

impl From<Es256KR> for AnyES {
    fn from(_value: Es256KR) -> Self {
        Self::ES256KR
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyBlake2b {
    EdBlake2b,
    ESBlake2bK,
    ESBlake2b,
}

impl SignatureAlgorithmType for AnyBlake2b {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyBlake2b {
    type Algorithm = Self;

    fn algorithm(&self) -> AnyBlake2b {
        *self
    }
}

impl From<AnyBlake2b> for Algorithm {
    fn from(value: AnyBlake2b) -> Self {
        match value {
            AnyBlake2b::EdBlake2b => Self::EdBlake2b,
            AnyBlake2b::ESBlake2bK => Self::EsBlake2bK,
            AnyBlake2b::ESBlake2b => Self::EsBlake2b,
        }
    }
}

impl From<AnyBlake2b> for AlgorithmInstance {
    fn from(value: AnyBlake2b) -> Self {
        match value {
            AnyBlake2b::EdBlake2b => Self::EdBlake2b,
            AnyBlake2b::ESBlake2bK => Self::EsBlake2bK,
            AnyBlake2b::ESBlake2b => Self::EsBlake2b,
        }
    }
}

impl TryFrom<Algorithm> for AnyBlake2b {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::EdBlake2b => Ok(Self::EdBlake2b),
            Algorithm::EsBlake2bK => Ok(Self::ESBlake2bK),
            Algorithm::EsBlake2b => Ok(Self::ESBlake2b),
            a => Err(UnsupportedAlgorithm(a)),
        }
    }
}

impl TryFrom<AlgorithmInstance> for AnyBlake2b {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: AlgorithmInstance) -> Result<Self, Self::Error> {
        match value {
            AlgorithmInstance::EdBlake2b => Ok(Self::EdBlake2b),
            AlgorithmInstance::EsBlake2bK => Ok(Self::ESBlake2bK),
            AlgorithmInstance::EsBlake2b => Ok(Self::ESBlake2b),
            a => Err(UnsupportedAlgorithm(a.algorithm())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ES256OrES384 {
    ES256,
    ES384,
}

impl ES256OrES384 {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
        }
    }
}

impl SignatureAlgorithmType for ES256OrES384 {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for ES256OrES384 {
    type Algorithm = Self;

    fn algorithm(&self) -> Self {
        *self
    }
}

impl fmt::Display for ES256OrES384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

impl From<ES256OrES384> for Algorithm {
    fn from(value: ES256OrES384) -> Self {
        match value {
            ES256OrES384::ES256 => Self::Es256,
            ES256OrES384::ES384 => Self::Es384,
        }
    }
}

impl From<ES256OrES384> for AlgorithmInstance {
    fn from(value: ES256OrES384) -> Self {
        match value {
            ES256OrES384::ES256 => Self::Es256,
            ES256OrES384::ES384 => Self::Es384,
        }
    }
}
