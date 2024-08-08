use crate::{Algorithm, AlgorithmInstance, SecretKey};

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(Algorithm),

    #[error("secret key is not compatible with the signature algorithm")]
    IncompatibleKey,
}

impl AlgorithmInstance {
    #[allow(unused)]
    pub fn sign(&self, key: &SecretKey, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        match self {
            #[cfg(feature = "secp256r1")]
            Self::ES256 => {
                match key {
                    SecretKey::P256(key) => {
                        use p256::ecdsa::{signature::Signer, Signature};
                        let signing_key = p256::ecdsa::SigningKey::from(key);
                        let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-256 by default.
                        Ok(signature.to_bytes().to_vec())
                    }
                    #[allow(unreachable_patterns)]
                    _ => Err(SignatureError::IncompatibleKey),
                }
            }
            #[cfg(feature = "secp384r1")]
            Self::ES384 => {
                match key {
                    SecretKey::P384(key) => {
                        use p384::ecdsa::{signature::Signer, Signature};
                        let signing_key = p384::ecdsa::SigningKey::from(key);
                        let signature: Signature = signing_key.try_sign(signing_bytes).unwrap(); // Uses SHA-384 by default.
                        Ok(signature.to_bytes().to_vec())
                    }
                    #[allow(unreachable_patterns)]
                    _ => Err(SignatureError::IncompatibleKey),
                }
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
