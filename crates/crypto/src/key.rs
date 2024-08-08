use zeroize::ZeroizeOnDrop;

use crate::{AlgorithmInstance, SignatureError, VerificationError};

pub struct InvalidPublicKey;

/// Public key.
#[non_exhaustive]
pub enum PublicKey {
    #[cfg(feature = "secp256k1")]
    Secp256k1(k256::PublicKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::PublicKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::PublicKey),
}

impl PublicKey {
    #[cfg(feature = "secp256k1")]
    pub fn new_secp256k1(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        k256::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::Secp256k1)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp256r1")]
    pub fn new_p256(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        p256::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::P256)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp384r1")]
    pub fn new_p384(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        p384::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::P384)
            .map_err(|_| InvalidPublicKey)
    }

    pub fn verify(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        algorithm.verify(self, signing_bytes, signature_bytes)
    }
}

/// Secret key.
#[derive(ZeroizeOnDrop)]
#[non_exhaustive]
pub enum SecretKey {
    #[cfg(feature = "secp256k1")]
    Secp256k1(k256::SecretKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::SecretKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::SecretKey),
}

impl SecretKey {
    #[cfg(feature = "secp256k1")]
    pub fn new_secp256k1(d: &[u8]) -> Result<Self, InvalidPublicKey> {
        k256::SecretKey::from_bytes(d.into())
            .map(Self::Secp256k1)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp256k1")]
    pub fn generate_secp256k1() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_secp256k1_from(&mut rng)
    }

    #[cfg(feature = "secp256k1")]
    pub fn generate_secp256k1_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::Secp256k1(k256::SecretKey::random(rng))
    }

    #[cfg(feature = "secp256r1")]
    pub fn new_p256(d: &[u8]) -> Result<Self, InvalidPublicKey> {
        p256::SecretKey::from_bytes(d.into())
            .map(Self::P256)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp256r1")]
    pub fn generate_p256() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p256_from(&mut rng)
    }

    #[cfg(feature = "secp256r1")]
    pub fn generate_p256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P256(p256::SecretKey::random(rng))
    }

    #[cfg(feature = "secp384r1")]
    pub fn new_p384(d: &[u8]) -> Result<Self, InvalidPublicKey> {
        p384::SecretKey::from_bytes(d.into())
            .map(Self::P384)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp384r1")]
    pub fn generate_p384() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p384_from(&mut rng)
    }

    #[cfg(feature = "secp384r1")]
    pub fn generate_p384_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P384(p384::SecretKey::random(rng))
    }

    pub fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, SignatureError> {
        algorithm.sign(self, signing_bytes)
    }
}
