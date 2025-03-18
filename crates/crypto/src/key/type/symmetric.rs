use std::ops::Deref;

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

impl Deref for SymmetricKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
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
    fn sign_message(
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
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Symmetric(self.0.len())),
            ..Default::default()
        }
    }

    fn verify_message(
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
