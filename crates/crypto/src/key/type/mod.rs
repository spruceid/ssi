use super::{KeyGenerationFailed, SecretKey};
use crate::{AlgorithmInstance, BitSize, ByteSize};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::borrow::Cow;

pub mod symmetric;
pub use symmetric::SymmetricKey;

#[cfg(feature = "rsa")]
pub mod rsa;
#[cfg(feature = "rsa")]
pub use rsa::{RsaPublicKey, RsaSecretKey};

pub mod ecdsa;
pub use ecdsa::{EcdsaCurve, EcdsaPublicKey, EcdsaSecretKey};

pub mod eddsa;
pub use eddsa::{EdDsaCurve, EdDsaPublicKey, EdDsaSecretKey};

/// Key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyType {
    /// Symmetric key.
    Symmetric(ByteSize),

    /// RSA key.
    ///
    /// Implementation requires the `rsa` feature.
    Rsa(BitSize),

    /// ECDSA key.
    Ecdsa(EcdsaCurve),

    /// EdDSA key.
    EdDsa(EdDsaCurve),
}

impl KeyType {
    pub fn name(&self) -> Cow<'static, str> {
        match self {
            Self::Symmetric(n) => Cow::Owned(format!("SYM-{}", n * 8)),
            Self::Rsa(BitSize(1024)) => Cow::Borrowed("RSA-1024"),
            Self::Rsa(BitSize(2048)) => Cow::Borrowed("RSA-2048"),
            Self::Rsa(BitSize(3072)) => Cow::Borrowed("RSA-3072"),
            Self::Rsa(BitSize(4096)) => Cow::Borrowed("RSA-4096"),
            Self::Rsa(n) => Cow::Owned(format!("RSA-{n}")),
            Self::Ecdsa(t) => Cow::Borrowed(t.name()),
            Self::EdDsa(t) => Cow::Borrowed(t.name()),
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(t) = EcdsaCurve::from_name(name) {
            return Some(Self::Ecdsa(t));
        }

        if let Some(t) = EdDsaCurve::from_name(name) {
            return Some(Self::EdDsa(t));
        }

        match name {
            "RSA-1024" => Some(Self::Rsa(BitSize(1024))),
            "RSA-2048" => Some(Self::Rsa(BitSize(2048))),
            "RSA-3072" => Some(Self::Rsa(BitSize(3072))),
            "RSA-4096" => Some(Self::Rsa(BitSize(4096))),
            _ => {
                if let Some(n) = name.strip_prefix("RSA-") {
                    return Some(Self::Rsa(n.parse().ok()?));
                }

                if let Some(n) = name.strip_prefix("SYM-") {
                    return Some(Self::Symmetric(
                        n.parse().ok().and_then(bit_len_to_byte_len)?,
                    ));
                }

                None
            }
        }
    }

    pub fn generate(&self) -> Result<SecretKey, KeyGenerationFailed> {
        self.generate_from(&mut OsRng)
    }

    pub fn generate_from(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<SecretKey, KeyGenerationFailed> {
        match self {
            Self::Symmetric(byte_len) => Ok(SecretKey::Symmetric(SymmetricKey::generate_from(
                *byte_len, rng,
            ))),
            #[cfg(feature = "rsa")]
            Self::Rsa(bit_len) => SecretKey::generate_rsa_from(*bit_len, rng),
            Self::Ecdsa(t) => t.generate_from(rng).map(SecretKey::Ecdsa),
            Self::EdDsa(t) => t.generate_from(rng).map(SecretKey::EdDsa),
            #[allow(unreachable_patterns)]
            _ => Err(KeyGenerationFailed::UnsupportedType),
        }
    }

    pub fn default_algorithm_params(&self) -> Option<AlgorithmInstance> {
        match self {
            Self::Symmetric(_) => Some(AlgorithmInstance::Hs256),
            Self::Rsa(_) => Some(AlgorithmInstance::Rs256),
            Self::EdDsa(t) => Some(t.default_algorithm_params()),
            Self::Ecdsa(t) => Some(t.default_algorithm_params()),
        }
    }
}

/// Converts the given bit-size and a byte-size.
///
/// This function does not make any approximation. If the bit-size is not a
/// multiple of 8, it will return `None`.
fn bit_len_to_byte_len(bit_len: usize) -> Option<usize> {
    if bit_len % 8 == 0 {
        Some(bit_len / 8)
    } else {
        None
    }
}
