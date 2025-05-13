use std::ops::Deref;

use rand::{rngs::OsRng, CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::{
    key::KeyMetadata, AlgorithmInstance, Error, SecretKey, SignatureVerification, SigningKey,
    VerifyingKey,
};

use super::KeyType;

#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey(Vec<u8>);

impl SymmetricKey {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Generates a new symmetric key of specified byte length.
    ///
    /// # Examples
    /// ```
    /// let key = ssi_crypto::key::SymmetricKey::generate(32); // Generate a 256-bit key
    /// ```
    pub fn generate(len: usize) -> Self {
        Self::generate_from(len, &mut OsRng)
    }

    /// Generates a new symmetric key of specified byte length using the
    /// provided cryptographic random number generator.
    ///
    /// # Examples
    /// ```
    /// use rand::rngs::OsRng;
    ///
    /// let key = ssi_crypto::key::SymmetricKey::generate_from(32, &mut OsRng); // Generate a 256-bit key
    /// ```
    pub fn generate_from(len: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = vec![0; len];
        rng.fill_bytes(bytes.as_mut_slice());
        Self::new(bytes)
    }
}

impl SecretKey {
    pub fn new_symmetric(value: Vec<u8>) -> Self {
        Self::Symmetric(SymmetricKey::new(value))
    }

    /// Generates a new symmetric key of specified byte length.
    ///
    /// # Examples
    /// ```
    /// let key = ssi_crypto::SecretKey::generate_symmetric(32); // Generate a 256-bit key
    /// ```
    pub fn generate_symmetric(len: usize) -> Self {
        Self::Symmetric(SymmetricKey::generate(len))
    }

    /// Generates a new symmetric key of specified byte length using the
    /// provided cryptographic random number generator.
    ///
    /// # Examples
    /// ```
    /// use rand::rngs::OsRng;
    ///
    /// let key = ssi_crypto::SecretKey::generate_symmetric_from(32, &mut OsRng); // Generate a 256-bit key
    /// ```
    pub fn generate_symmetric_from(len: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::Symmetric(SymmetricKey::generate_from(len, rng))
    }
}

impl Deref for SymmetricKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SymmetricKey {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<Box<[u8]>> for SymmetricKey {
    fn from(value: Box<[u8]>) -> Self {
        Self::new(value.into_vec())
    }
}

impl SigningKey for SymmetricKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        _signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // TODO we should implement those algorithms for symmetric keys,
        // but since it's not implemented in `ssi_jws`, I'll not bother for
        // now.
        // match algorithm.into() {
        //     AlgorithmInstance::HS256 => {
        //         todo!()
        //     }
        //     AlgorithmInstance::HS384 => {
        //         todo!()
        //     }
        //     AlgorithmInstance::HS512 => {
        //         todo!()
        //     }
        //     other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        // }
        Err(Error::AlgorithmUnsupported(algorithm.into().algorithm()))
    }
}

impl VerifyingKey for SymmetricKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            r#type: Some(KeyType::Symmetric(self.0.len())),
            ..Default::default()
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        _signing_bytes: &[u8],
        _signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        // TODO we should implement those algorithms for symmetric keys,
        // but since it's not implemented in `ssi_jws`, I'll not bother for
        // now.
        // match algorithm.into() {
        //     AlgorithmInstance::HS256 => {
        //         todo!()
        //     }
        //     AlgorithmInstance::HS384 => {
        //         todo!()
        //     }
        //     AlgorithmInstance::HS512 => {
        //         todo!()
        //     }
        //     other => Err(Error::AlgorithmUnsupported(other.algorithm())),
        // }
        Err(Error::AlgorithmUnsupported(algorithm.into().algorithm()))
    }
}
