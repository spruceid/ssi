use serde::de::DeserializeOwned;
use ssi_claims_core::{DateTimeProvider, ProofValidationError, ResolverProvider, Verification};
use ssi_jwk::JWKResolver;
use ssi_jws::{DecodeError as JWSDecodeError, DecodedJws, JwsSlice, JwsStr, JwsString, JwsVec};

use crate::{AnyClaims, JWTClaims};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid JWS: {0}")]
    JWS(#[from] JWSDecodeError),

    #[error("invalid JWT claims: {0}")]
    Claims(#[from] serde_json::Error),
}

impl From<DecodeError> for ProofValidationError {
    fn from(value: DecodeError) -> Self {
        Self::InvalidInputData(value.to_string())
    }
}

/// Decoded JWT.
///
/// By definition this is a decoded JWS with JWT claims as payload.
pub type DecodedJwt<'a, T = AnyClaims> = DecodedJws<'a, JWTClaims<T>>;

/// JWT borrowing decoding.
pub trait ToDecodedJwt {
    /// Decodes a JWT with custom claims.
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJwt<C>, DecodeError>;

    /// Decodes a JWT.
    fn to_decoded_jwt(&self) -> Result<DecodedJwt, DecodeError> {
        self.to_decoded_custom_jwt::<AnyClaims>()
    }

    /// Verify the JWS signature.
    ///
    /// This check the signature and the validity of registered claims.
    #[allow(async_fn_in_trait)]
    async fn verify_jwt<V>(&self, verifier: &V) -> Result<Verification, ProofValidationError>
    where
        V: ResolverProvider + DateTimeProvider,
        V::Resolver: JWKResolver,
    {
        self.to_decoded_jwt()?.verify(verifier).await
    }
}

/// JWT consuming decoding.
pub trait IntoDecodedJwt: Sized {
    /// Decodes a JWT with custom claims.
    fn into_decoded_custom_jwt<C: DeserializeOwned>(
        self,
    ) -> Result<DecodedJwt<'static, C>, DecodeError>;

    fn into_decoded_jwt(self) -> Result<DecodedJwt<'static>, DecodeError> {
        self.into_decoded_custom_jwt::<AnyClaims>()
    }
}

impl ToDecodedJwt for JwsSlice {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJwt<C>, DecodeError> {
        self.decode()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}

impl ToDecodedJwt for JwsStr {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJwt<C>, DecodeError> {
        JwsSlice::to_decoded_custom_jwt(self)
    }
}

impl ToDecodedJwt for JwsVec {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJwt<C>, DecodeError> {
        JwsSlice::to_decoded_custom_jwt(self)
    }
}

impl IntoDecodedJwt for JwsVec {
    fn into_decoded_custom_jwt<C: DeserializeOwned>(
        self,
    ) -> Result<DecodedJwt<'static, C>, DecodeError> {
        self.into_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}

impl ToDecodedJwt for JwsString {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJwt<C>, DecodeError> {
        JwsSlice::to_decoded_custom_jwt(self)
    }
}

impl IntoDecodedJwt for JwsString {
    fn into_decoded_custom_jwt<C: DeserializeOwned>(
        self,
    ) -> Result<DecodedJwt<'static, C>, DecodeError> {
        self.into_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}
