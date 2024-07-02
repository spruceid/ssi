use serde::de::DeserializeOwned;
use ssi_claims_core::{DateTimeProvider, ProofValidationError, ResolverProvider, Verification};
use ssi_jwk::JWKResolver;
use ssi_jws::{
    CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, DecodeError as JWSDecodeError,
    DecodedJWS,
};

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
pub type DecodedJWT<T = AnyClaims> = DecodedJWS<JWTClaims<T>>;

/// JWT borrowing decoding.
pub trait ToDecodedJWT {
    /// Decodes a JWT with custom claims.
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJWT<C>, DecodeError>;

    /// Decodes a JWT.
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError> {
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
pub trait IntoDecodedJWT: Sized {
    /// Decodes a JWT with custom claims.
    fn into_decoded_custom_jwt<C: DeserializeOwned>(self) -> Result<DecodedJWT<C>, DecodeError>;

    fn into_decoded_jwt(self) -> Result<DecodedJWT, DecodeError> {
        self.into_decoded_custom_jwt::<AnyClaims>()
    }
}

impl ToDecodedJWT for CompactJWS {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJWT<C>, DecodeError> {
        self.to_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}

impl ToDecodedJWT for CompactJWSStr {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJWT<C>, DecodeError> {
        CompactJWS::to_decoded_custom_jwt(self)
    }
}

impl ToDecodedJWT for CompactJWSBuf {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJWT<C>, DecodeError> {
        CompactJWS::to_decoded_custom_jwt(self)
    }
}

impl IntoDecodedJWT for CompactJWSBuf {
    fn into_decoded_custom_jwt<C: DeserializeOwned>(self) -> Result<DecodedJWT<C>, DecodeError> {
        self.into_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}

impl ToDecodedJWT for CompactJWSString {
    fn to_decoded_custom_jwt<C: DeserializeOwned>(&self) -> Result<DecodedJWT<C>, DecodeError> {
        CompactJWS::to_decoded_custom_jwt(self)
    }
}

impl IntoDecodedJWT for CompactJWSString {
    fn into_decoded_custom_jwt<C: DeserializeOwned>(self) -> Result<DecodedJWT<C>, DecodeError> {
        self.into_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}
