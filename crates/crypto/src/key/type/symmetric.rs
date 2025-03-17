use zeroize::ZeroizeOnDrop;

use crate::{
    key::KeyMetadata, AlgorithmInstance, Error, SignatureVerification, SigningKey, VerifyingKey,
};

use super::KeyType;

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
        _signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
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
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}

impl VerifyingKey for SymmetricKey {
    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Symmetric),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        _signing_bytes: &[u8],
        _signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
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
            other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        }
    }
}
