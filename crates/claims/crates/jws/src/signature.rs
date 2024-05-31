use ssi_claims_core::SignatureError;
use ssi_jwk::{Algorithm, JWK};
use std::borrow::Cow;

use crate::{CompactJWSString, Header};

/// JWS payload type.
///
/// Any type that can be serialized with a give JWS type.
pub trait JWSPayload {
    /// JWS type.
    ///
    /// Value of the `typ` field in the JWS header.
    fn typ(&self) -> Option<&'static str>;

    fn payload_bytes(&self) -> Cow<[u8]>;

    /// Signs the payload and returns a compact JWS.
    #[allow(async_fn_in_trait)]
    async fn sign(&self, signer: &impl JWSSigner) -> Result<CompactJWSString, SignatureError> {
        signer.sign(self).await
    }
}

impl JWSPayload for [u8] {
    fn typ(&self) -> Option<&'static str> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

impl JWSPayload for Vec<u8> {
    fn typ(&self) -> Option<&'static str> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

impl JWSPayload for str {
    fn typ(&self) -> Option<&'static str> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl JWSPayload for String {
    fn typ(&self) -> Option<&'static str> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

pub struct JWSSignerInfo {
    pub key_id: Option<String>,
    pub algorithm: Algorithm,
}

/// JWS Signer.
///
/// Any type that can fetch a JWK using the `kid` parameter of a JWS JOSE
/// header and sign bytes.
pub trait JWSSigner {
    #[allow(async_fn_in_trait)]
    async fn fetch_info(&self) -> Result<JWSSignerInfo, SignatureError>;

    #[allow(async_fn_in_trait)]
    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError>;

    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        payload: &(impl ?Sized + JWSPayload),
    ) -> Result<CompactJWSString, SignatureError> {
        let info = self.fetch_info().await?;
        let payload_bytes = payload.payload_bytes();

        let header = Header {
            algorithm: info.algorithm,
            key_id: info.key_id,
            type_: payload.typ().map(ToOwned::to_owned),
            ..Default::default()
        };

        let signing_bytes = header.encode_signing_bytes(&payload_bytes);
        let signature = self.sign_bytes(&signing_bytes).await?;

        Ok(
            CompactJWSString::encode_from_signing_bytes_and_signature(signing_bytes, &signature)
                .unwrap(),
        )
    }
}

impl<'a, T: JWSSigner> JWSSigner for &'a T {
    async fn fetch_info(&self) -> Result<JWSSignerInfo, SignatureError> {
        T::fetch_info(*self).await
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        T::sign_bytes(*self, signing_bytes).await
    }

    async fn sign(
        &self,
        payload: &(impl ?Sized + JWSPayload),
    ) -> Result<CompactJWSString, SignatureError> {
        T::sign(*self, payload).await
    }
}

impl<'a, T: JWSSigner + Clone> JWSSigner for Cow<'a, T> {
    async fn fetch_info(&self) -> Result<JWSSignerInfo, SignatureError> {
        T::fetch_info(self.as_ref()).await
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        T::sign_bytes(self.as_ref(), signing_bytes).await
    }

    async fn sign(
        &self,
        payload: &(impl ?Sized + JWSPayload),
    ) -> Result<CompactJWSString, SignatureError> {
        T::sign(self.as_ref(), payload).await
    }
}

impl JWSSigner for JWK {
    async fn fetch_info(&self) -> Result<JWSSignerInfo, SignatureError> {
        Ok(JWSSignerInfo {
            key_id: self.key_id.clone(),
            algorithm: self
                .get_algorithm()
                .ok_or(SignatureError::MissingAlgorithm)?,
        })
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let algorithm = self
            .get_algorithm()
            .ok_or(SignatureError::MissingAlgorithm)?;
        crate::sign_bytes(algorithm, signing_bytes, self).map_err(Into::into)
    }
}

pub struct JWKWithAlgorithm<'a> {
    pub jwk: &'a JWK,
    pub algorithm: Algorithm,
}

impl<'a> JWKWithAlgorithm<'a> {
    pub fn new(jwk: &'a JWK, algorithm: Algorithm) -> Self {
        Self { jwk, algorithm }
    }
}

impl<'a> JWSSigner for JWKWithAlgorithm<'a> {
    async fn fetch_info(&self) -> Result<JWSSignerInfo, SignatureError> {
        Ok(JWSSignerInfo {
            key_id: self.jwk.key_id.clone(),
            algorithm: self.algorithm,
        })
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        crate::sign_bytes(self.algorithm, signing_bytes, self.jwk).map_err(Into::into)
    }
}
