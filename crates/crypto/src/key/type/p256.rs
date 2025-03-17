use crate::{
    key::{KeyConversionError, KeyMetadata}, AlgorithmInstance, Error, PublicKey, RejectedSignature, SecretKey, SignatureVerification, SigningKey, VerifyingKey
};
pub use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};

use super::KeyType;

impl PublicKey {
    /// Creates a new ECDSA P-256 public key.
    pub fn new_ecdsa_p256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);
        Self::from_ecdsa_p256_sec1_bytes(&bytes)
    }

    /// Decodes an ECDSA P-256 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_ecdsa_p256_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        P256PublicKey::from_sec1_bytes(bytes)
            .map(Self::P256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for P256PublicKey {
    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::P256),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        match algorithm.into() {
            AlgorithmInstance::ES256 => {
                use p256::ecdsa::signature::Verifier;
                let verifying_key = p256::ecdsa::VerifyingKey::from(self);
                let sig = p256::ecdsa::Signature::try_from(signature)
                	.map_err(|_| Error::SignatureMalformed)?;
                let verification = verifying_key.verify(signing_bytes, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            AlgorithmInstance::ESBlake2b => {
                todo!()
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_ecdsa_p256() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_ecdsa_p256_from(&mut rng)
    }

    pub fn generate_ecdsa_p256_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::P256(P256SecretKey::random(rng))
    }

    pub fn new_ecdsa_p256(d: &[u8]) -> Result<Self, KeyConversionError> {
        p256::SecretKey::from_bytes(d.into())
            .map(Self::P256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for P256SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        match algorithm.into() {
            AlgorithmInstance::ES256 => {
                use p256::ecdsa::{signature::Signer, Signature};
                let signing_key = p256::ecdsa::SigningKey::from(self);
                let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                Ok(signature.to_bytes().as_slice().into())
            }
            AlgorithmInstance::ESBlake2b => {
                todo!()
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}
