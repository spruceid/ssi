use crate::{Algorithm, AlgorithmInstance, PublicKey};

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(Algorithm),

    #[error("secret key is not compatible with the signature algorithm")]
    IncompatibleKey,

    #[error("invalid signature")]
    InvalidSignature,
}

impl AlgorithmInstance {
    #[allow(unused)]
    pub fn verify(
        &self,
        key: &PublicKey,
        signing_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::EdDSA => match key {
                PublicKey::Ed25519(key) => {
                    use ed25519_dalek::Verifier;
                    let signature: ed25519_dalek::Signature = signature_bytes
                        .try_into()
                        .map_err(|_| VerificationError::InvalidSignature)?;
                    Ok(key.verify(signing_bytes, &signature).is_ok())
                }
                #[allow(unreachable_patterns)]
                _ => Err(VerificationError::IncompatibleKey),
            },
            #[cfg(feature = "secp256k1")]
            Self::ES256K => match key {
                PublicKey::Secp256k1(key) => {
                    use k256::ecdsa::signature::Verifier;
                    let verifying_key = k256::ecdsa::VerifyingKey::from(key);
                    let sig = k256::ecdsa::Signature::try_from(signature_bytes)
                        .map_err(|_| VerificationError::InvalidSignature)?;
                    Ok(verifying_key.verify(signing_bytes, &sig).is_ok())
                }
                #[allow(unreachable_patterns)]
                _ => Err(VerificationError::IncompatibleKey),
            },
            #[cfg(feature = "secp256r1")]
            Self::ES256 => match key {
                PublicKey::P256(key) => {
                    use p256::ecdsa::signature::Verifier;
                    let verifying_key = p256::ecdsa::VerifyingKey::from(key);
                    let sig = p256::ecdsa::Signature::try_from(signature_bytes)
                        .map_err(|_| VerificationError::InvalidSignature)?;
                    Ok(verifying_key.verify(signing_bytes, &sig).is_ok())
                }
                #[allow(unreachable_patterns)]
                _ => Err(VerificationError::IncompatibleKey),
            },
            #[cfg(feature = "secp384r1")]
            Self::ES384 => match key {
                PublicKey::P384(key) => {
                    use p384::ecdsa::signature::Verifier;
                    let verifying_key = p384::ecdsa::VerifyingKey::from(key);
                    let sig = p384::ecdsa::Signature::try_from(signature_bytes)
                        .map_err(|_| VerificationError::InvalidSignature)?;
                    Ok(verifying_key.verify(signing_bytes, &sig).is_ok())
                }
                #[allow(unreachable_patterns)]
                _ => Err(VerificationError::IncompatibleKey),
            },
            other => Err(VerificationError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
