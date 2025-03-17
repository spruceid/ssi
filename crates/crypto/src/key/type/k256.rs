use crate::{
    key::{KeyConversionError, KeyMetadata}, AlgorithmInstance, Error, PublicKey, RejectedSignature, SecretKey, SigningKey, VerifyingKey
};
pub use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};

use super::KeyType;

impl PublicKey {
    /// Creates a new ECDSA K-256 public key.
    pub fn new_ecdsa_k256(x: &[u8], y: &[u8]) -> Result<Self, KeyConversionError> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);
        Self::from_ecdsa_k256_sec1_bytes(&bytes)
    }

    /// Decodes an ECDSA P-256 [`PublicKey`] (compressed or uncompressed) from
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// See: <http://www.secg.org/sec1-v2.pdf>
    pub fn from_ecdsa_k256_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        K256PublicKey::from_sec1_bytes(bytes)
            .map(Self::K256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl VerifyingKey for K256PublicKey {
    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::K256),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<crate::SignatureVerification, crate::Error> {
        match algorithm.into() {
            AlgorithmInstance::ES256K => {
                use k256::ecdsa::signature::Verifier;
                let verifying_key = k256::ecdsa::VerifyingKey::from(self);
                let sig = k256::ecdsa::Signature::try_from(signature)
                	.map_err(|_| Error::SignatureMalformed)?;
                let verification = verifying_key.verify(signing_bytes, &sig);
                Ok(verification.map_err(|_| RejectedSignature::Mismatch))
            }
            AlgorithmInstance::ES256KR => {
                todo!()
            }
            AlgorithmInstance::ESBlake2bK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakKR => {
                todo!()
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl SecretKey {
    pub fn generate_secp256k1() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_secp256k1_from(&mut rng)
    }

    pub fn generate_secp256k1_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::K256(k256::SecretKey::random(rng))
    }

    pub fn new_secp256k1(d: &[u8]) -> Result<Self, KeyConversionError> {
        k256::SecretKey::from_bytes(d.into())
            .map(Self::K256)
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl SigningKey for K256SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        let signing_key = SigningKey::from(self);

        match algorithm.into() {
            AlgorithmInstance::ES256K => {
                let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                Ok(signature.to_bytes().to_vec().into_boxed_slice())
            }
            AlgorithmInstance::ES256KR => {
                todo!()
            }
            AlgorithmInstance::ESBlake2bK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakK => {
                todo!()
            }
            AlgorithmInstance::ESKeccakKR => {
                todo!()
            }
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}
