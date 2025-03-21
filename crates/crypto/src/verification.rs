use crate::{key::KeyMetadata, AlgorithmInstance, Error, Options};

/// Verifier.
///
/// Any object capable of verifying a message signed with a given algorithm.
pub trait Verifier {
    /// Verifying key type.
    type VerifyingKey: VerifyingKey;

    /// Returns the verifying key with the given `id` and options, if any.
    #[allow(async_fn_in_trait)]
    async fn get_verifying_key_with(
        &self,
        id: Option<&[u8]>,
        options: &Options,
    ) -> Result<Option<Self::VerifyingKey>, Error>;

    /// Returns the verifying key with the given `id`, if any.
    #[allow(async_fn_in_trait)]
    async fn get_verifying_key(
        &self,
        id: Option<&[u8]>,
    ) -> Result<Option<Self::VerifyingKey>, Error> {
        let options = Options::default();
        self.get_verifying_key_with(id, &options).await
    }

    /// Returns the verifying key with the given `id` and options, or returns
    /// an error if there is none.
    #[allow(async_fn_in_trait)]
    async fn require_verifying_key_with(
        &self,
        id: Option<&[u8]>,
        options: &Options,
    ) -> Result<Self::VerifyingKey, Error> {
        self.get_verifying_key_with(id, options)
            .await?
            .ok_or_else(|| Error::KeyNotFound(id.map(|id| id.to_vec())))
    }

    /// Returns the verifying key with the given `id`, or returns an error if
    /// there is none.
    #[allow(async_fn_in_trait)]
    async fn require_verifying_key(&self, id: Option<&[u8]>) -> Result<Self::VerifyingKey, Error> {
        let options = Options::default();
        self.require_verifying_key_with(id, &options).await
    }

    /// Verifies a signature against the given message, using a specific key,
    /// algorithm and options.
    #[allow(async_fn_in_trait)]
    async fn verify_with(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
        options: &Options,
    ) -> Result<SignatureVerification, Error> {
        let key = self.require_verifying_key_with(key_id, options).await?;
        let (_, algorithm) = key.metadata().into_id_and_algorithm(algorithm)?;
        key.verify_bytes(algorithm, signing_bytes, signature)
    }

    /// Verifies a signature against the given message, using a specific key and
    /// algorithm.
    #[allow(async_fn_in_trait)]
    async fn verify(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        let options = Options::default();
        self.verify_with(key_id, algorithm, signing_bytes, signature, &options)
            .await
    }
}

impl<T: Verifier> Verifier for &T {
    type VerifyingKey = T::VerifyingKey;

    async fn get_verifying_key_with(
        &self,
        key_id: Option<&[u8]>,
        options: &Options,
    ) -> Result<Option<Self::VerifyingKey>, Error> {
        T::get_verifying_key_with(self, key_id, options).await
    }

    async fn verify_with(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
        options: &Options,
    ) -> Result<SignatureVerification, Error> {
        T::verify_with(*self, key_id, algorithm, signing_bytes, signature, options).await
    }
}

/// Verifying key.
///
/// Any object capable of directly verifying a message signed with a given
/// algorithm.
pub trait VerifyingKey {
    /// Returns the key's metadata.
    fn metadata(&self) -> KeyMetadata;

    /// Verifies a message signed with the given algorithm.
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error>;
}

/// Result of a signature verification.
pub type SignatureVerification = Result<(), RejectedSignature>;

/// Cause of a rejected signature.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RejectedSignature {
    #[error("missing signature")]
    Missing,

    #[error("signature mismatch")]
    Mismatch,
}
