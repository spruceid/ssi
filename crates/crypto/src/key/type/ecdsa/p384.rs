use crate::{
    key::{KeyConversionError, KeyMetadata},
    AlgorithmInstance, Error, KeyType, PublicKey, RejectedSignature, SecretKey, SigningKey,
    VerifyingKey,
};
pub use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};

use super::{EcdsaKeyType, EcdsaPublicKey, EcdsaSecretKey};

impl PublicKey {
    /// Creates a new ECDSA P-384 public key.
    pub fn new_ecdsa_p384(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaPublicKey::new_p384(x, y).map(Self::Ecdsa)
    }

    /// Decodes an ECDSA P-384 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_ecdsa_p384_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaPublicKey::from_p384_sec1_bytes(bytes).map(Self::Ecdsa)
    }
}

impl EcdsaPublicKey {
    /// Creates a new ECDSA P-384 public key.
    pub fn new_p384(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);
        Self::from_p384_sec1_bytes(&bytes)
    }

    /// Decodes an ECDSA P-384 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_p384_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        P384PublicKey::from_sec1_bytes(bytes)
            .map(Self::P384)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for P384PublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Ecdsa(EcdsaKeyType::P384)),
            ..Default::default()
        }
    }

    fn verify_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<crate::SignatureVerification, crate::Error> {
        match algorithm.into() {
            AlgorithmInstance::ES384 => {
                use p384::ecdsa::signature::Verifier;
                let verifying_key = p384::ecdsa::VerifyingKey::from(self);
                let sig = p384::ecdsa::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMalformed)?;
                let verification = verifying_key.verify(signing_bytes, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_ecdsa_p384() -> Self {
        Self::Ecdsa(EcdsaSecretKey::generate_p384())
    }

    pub fn generate_ecdsa_p384_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::Ecdsa(EcdsaSecretKey::generate_p384_from(rng))
    }

    pub fn new_ecdsa_p384(d: &[u8]) -> Result<Self, KeyConversionError> {
        EcdsaSecretKey::new_p384(d).map(Self::Ecdsa)
    }
}

impl EcdsaSecretKey {
    pub fn generate_p384() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p384_from(&mut rng)
    }

    pub fn generate_p384_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P384(p384::SecretKey::random(rng))
    }

    pub fn new_p384(d: &[u8]) -> Result<Self, KeyConversionError> {
        p384::SecretKey::from_bytes(d.into())
            .map(Self::P384)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for P384SecretKey {
    fn sign_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        match algorithm.into() {
            AlgorithmInstance::ES384 => {
                use p384::ecdsa::{signature::Signer, Signature};
                let signing_key = p384::ecdsa::SigningKey::from(self);
                let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-384 by default.
                Ok(signature.to_bytes().as_slice().into())
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}
