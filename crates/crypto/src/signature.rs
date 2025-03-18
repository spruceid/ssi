use std::sync::Arc;

use crate::{key::KeyMetadata, AlgorithmInstance, Error};

/// Issuer.
pub trait Issuer {
    type Signer: Signer;

    #[allow(async_fn_in_trait)]
    async fn signer(&self, key_id: Option<&[u8]>) -> Result<Option<Self::Signer>, Error>;

    #[allow(async_fn_in_trait)]
    async fn require_signer(&self, key_id: Option<&[u8]>) -> Result<Self::Signer, Error> {
        self.signer(key_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(key_id.map(|id| id.to_vec())))
    }
}

/// Signer.
pub trait Signer {
    fn key_metadata(&self) -> KeyMetadata;

    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error>;
}

impl<'a, T: Signer> Signer for &'a T {
    fn key_metadata(&self) -> KeyMetadata {
        T::key_metadata(*self)
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        T::sign(*&self, algorithm, signing_bytes).await
    }
}

impl<T: Signer> Signer for Box<T> {
    fn key_metadata(&self) -> KeyMetadata {
        T::key_metadata(&*self)
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        T::sign(&*self, algorithm, signing_bytes).await
    }
}

impl<T: Signer> Signer for Arc<T> {
    fn key_metadata(&self) -> KeyMetadata {
        T::key_metadata(&*self)
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        T::sign(&*self, algorithm, signing_bytes).await
    }
}

pub trait SigningKey {
    fn sign_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error>;
}

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
#[cfg(feature = "der")]
pub fn decode_ecdsa_p256_signature_der(
    bytes: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, MalformedSignature> {
    p256::ecdsa::Signature::from_der(bytes.as_ref())
        .map(|s| s.to_bytes().to_vec().into_boxed_slice())
        .map_err(|_| MalformedSignature)
}
