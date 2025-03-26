use std::sync::Arc;

use crate::{key::KeyMetadata, AlgorithmInstance, Error};

// Re-export.
pub use signature;

/// Issuer.
///
/// Any object capable of providing a [`Signer`] for a given key.
pub trait Issuer {
    /// Signer type.
    type Signer: Signer;

    /// Returns a signer for the key identified by `key_id`, if any.
    #[allow(async_fn_in_trait)]
    async fn get_signer(&self, key_id: Option<&[u8]>) -> Result<Option<Self::Signer>, Error>;

    /// Returns a signer for the key identified by `key_id`, or fail if there
    /// isn't any.
    #[allow(async_fn_in_trait)]
    async fn require_signer(&self, key_id: Option<&[u8]>) -> Result<Self::Signer, Error> {
        self.get_signer(key_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(key_id.map(|id| id.to_vec())))
    }
}

/// Signer.
///
/// Any object capable of signing a message with the given cryptographic
/// algorithm instance.
pub trait Signer {
    /// Returns the signing key's metadata.
    fn metadata(&self) -> KeyMetadata;

    /// Signs a message with the given algorithm.
    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

impl<T: Signer> Signer for &T {
    fn metadata(&self) -> KeyMetadata {
        T::metadata(*self)
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        T::sign(self, algorithm, signing_bytes).await
    }
}

impl<T: Signer> Signer for Box<T> {
    fn metadata(&self) -> KeyMetadata {
        T::metadata(self)
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        T::sign(self, algorithm, signing_bytes).await
    }
}

impl<T: Signer> Signer for Arc<T> {
    fn metadata(&self) -> KeyMetadata {
        T::metadata(self)
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        T::sign(self, algorithm, signing_bytes).await
    }
}

/// Signing key.
///
/// Any object capable of directly signing a message with a given algorithm.
pub trait SigningKey {
    /// Signs a message with the given algorithm.
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

/// Error raised when a signature could not be parsed.
#[derive(Debug, thiserror::Error)]
#[error("malformed signature")]
pub struct MalformedSignature;

impl From<MalformedSignature> for Error {
    fn from(_value: MalformedSignature) -> Self {
        Error::SignatureMalformed
    }
}

/// Decode DER-encoded ECDSA P-256 signature as defined by ANSI X9.62–2005 and
/// [RFC 3279 Section 2.2.3].
///
/// [RFC 3279 Section 2.2.3]: <https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3>
#[cfg(all(feature = "secp256r1", feature = "der"))]
pub fn decode_ecdsa_p256_signature_der(
    bytes: impl AsRef<[u8]>,
) -> Result<Vec<u8>, MalformedSignature> {
    p256::ecdsa::Signature::from_der(bytes.as_ref())
        .map(|s| s.to_bytes().to_vec())
        .map_err(|_| MalformedSignature)
}
