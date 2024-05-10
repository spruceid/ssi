use ssi_claims_core::{ProofValidationError, VerifiableClaims, Verification};
use ssi_jws::{
    CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, DecodeError as JWSDecodeError,
    DecodedJWS, JWSVerifier,
};

use crate::JWTClaims;

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
pub type DecodedJWT = DecodedJWS<JWTClaims>;

/// JWT borrowing decoding.
pub trait ToDecodedJWT {
    fn to_decoded_jwt(&self) -> Result<DecodedJWT, DecodeError>;

    /// Verify the JWS signature.
    ///
    /// This check the signature and the validity of registered claims.
    #[allow(async_fn_in_trait)]
    async fn verify_jwt(
        &self,
        verifier: &impl JWSVerifier,
    ) -> Result<Verification, ProofValidationError> {
        self.to_decoded_jwt()?
            .into_verifiable()
            .await?
            .verify(verifier)
            .await
    }
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