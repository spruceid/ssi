use ssi_jws::{
    CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, DecodeError as JWSDecodeError,
    DecodedJWS,
};

use crate::JWTClaims;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid JWS: {0}")]
    JWS(#[from] JWSDecodeError),

    #[error("invalid JWT claims: {0}")]
    Claims(#[from] serde_json::Error),
}

/// Decoded JWT.
///
/// By definition this is a decoded JWS with JWT claims as payload.
pub type DecodedJWT = DecodedJWS<JWTClaims>;

/// JWT borrowing decoding.
pub trait ToDecodedJWT {
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError>;
}

/// JWT consuming decoding.
pub trait IntoDecodedJWT {
    fn into_decoded_jwt(self) -> Result<DecodedJWT, DecodeError>;
}

impl ToDecodedJWT for CompactJWS {
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError> {
        self.to_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}

impl ToDecodedJWT for CompactJWSStr {
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError> {
        CompactJWS::to_decoded_jwt(self)
    }
}

impl ToDecodedJWT for CompactJWSBuf {
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError> {
        CompactJWS::to_decoded_jwt(self)
    }
}

impl IntoDecodedJWT for CompactJWSBuf {
    fn into_decoded_jwt(self) -> Result<DecodedJWT, DecodeError> {
        self.into_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}

impl ToDecodedJWT for CompactJWSString {
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError> {
        CompactJWS::to_decoded_jwt(self)
    }
}

impl IntoDecodedJWT for CompactJWSString {
    fn into_decoded_jwt(self) -> Result<DecodedJWT, DecodeError> {
        self.into_decoded()?
            .try_map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    }
}
