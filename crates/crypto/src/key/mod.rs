use zeroize::ZeroizeOnDrop;

#[derive(Debug, thiserror::Error)]
#[error("invalid public key")]
pub struct InvalidPublicKey;

mod r#type;
pub use r#type::*;

pub mod metadata;
pub use metadata::KeyMetadata;

/// Public key.
#[non_exhaustive]
pub enum PublicKey {
    /// Symmetric key.
    ///
    /// Such key cannot be made public, that's why there is no payload.
    Symmetric,

    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::Ed25519PublicKey),

    #[cfg(feature = "rsa")]
    Rsa(rsa::RsaPublicKey),

    #[cfg(feature = "secp256k1")]
    K256(k256::K256PublicKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::P256PublicKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::P384PublicKey),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid secret key")]
pub struct InvalidSecretKey;

/// Secret key.
#[derive(ZeroizeOnDrop)]
#[non_exhaustive]
pub enum SecretKey {
    /// Symmetric key.
    Symmetric(symmetric::SymmetricKey),

    #[cfg(feature = "rsa")]
    Rsa(rsa::RsaSecretKey),

    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::Ed25519SecretKey),

    #[cfg(feature = "secp256k1")]
    K256(k256::K256SecretKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::P256SecretKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::P384SecretKey),
}

impl SecretKey {
    #[cfg(feature = "rsa")]
    pub fn as_rsa(&self) -> Option<&rsa::RsaSecretKey> {
        match self {
            Self::Rsa(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the public key to this secret key.
    pub fn to_public(&self) -> PublicKey {
        match self {
            Self::Symmetric(_) => PublicKey::Symmetric,

            #[cfg(feature = "rsa")]
            Self::Rsa(secret) => PublicKey::Rsa(secret.to_public_key()),

            #[cfg(feature = "ed25519")]
            Self::Ed25519(secret) => PublicKey::Ed25519(secret.verifying_key()),

            #[cfg(feature = "secp256k1")]
            Self::K256(secret) => PublicKey::K256(secret.public_key()),

            #[cfg(feature = "secp256r1")]
            Self::P256(secret) => PublicKey::P256(secret.public_key()),

            #[cfg(feature = "secp384r1")]
            Self::P384(secret) => PublicKey::P384(secret.public_key()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyConversionError {
    #[error("no secret material")]
    NotSecret,

    #[error("unsupported key type")]
    Unsupported,

    #[error("invalid key")]
    Invalid,
}

#[derive(Debug, thiserror::Error)]
#[error("key generation failed")]
pub struct KeyGenerationFailed;
