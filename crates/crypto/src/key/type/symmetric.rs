use zeroize::ZeroizeOnDrop;

use crate::{
    AlgorithmInstance, SignatureError, SigningKey, Verification, VerificationError, VerifyingKey,
};

#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey(Box<[u8]>);

impl SymmetricKey {
    pub fn new(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl From<Box<[u8]>> for SymmetricKey {
    fn from(value: Box<[u8]>) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for SymmetricKey {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value.into_boxed_slice())
    }
}

impl SigningKey for SymmetricKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        match algorithm.into() {
            AlgorithmInstance::HS256 => {
                todo!()
            }
            AlgorithmInstance::HS384 => {
                todo!()
            }
            AlgorithmInstance::HS512 => {
                todo!()
            }
            other => Err(SignatureError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}

impl VerifyingKey for SymmetricKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Verification, VerificationError> {
        match algorithm.into() {
            AlgorithmInstance::HS256 => {
                todo!()
            }
            AlgorithmInstance::HS384 => {
                todo!()
            }
            AlgorithmInstance::HS512 => {
                todo!()
            }
            other => Err(VerificationError::UnsupportedAlgorithm(other.algorithm())),
        }
    }
}
