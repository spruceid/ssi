use ssi_claims_core::SignatureError;

use crate::InvalidHeader;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Missing curve in JWK
    #[error("Missing curve in JWK")]
    MissingCurve,
    /// Curve not implemented
    #[error("Curve not implemented: '{0}'")]
    CurveNotImplemented(String),
    /// Errors from p256, k256 and ed25519-dalek
    #[cfg(feature = "k256")]
    #[error(transparent)]
    CryptoErr(#[from] k256::ecdsa::Error),
    #[cfg(all(feature = "p256", not(feature = "k256")))]
    #[error(transparent)]
    CryptoErr(#[from] p256::ecdsa::Error),
    #[cfg(all(feature = "p384", not(any(feature = "k256", feature = "p256"))))]
    #[error(transparent)]
    CryptoErr(#[from] p384::ecdsa::Error),
    #[error(transparent)]
    Jwk(#[from] ssi_jwk::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    /// Invalid `crit` property in JWT header
    #[error("Invalid crit property in JWT header")]
    InvalidCriticalHeader,
    /// Unknown `crit` header name in JWT header
    #[error("Unknown critical header name in JWT header")]
    UnknownCriticalHeader,
    /// Algorithm in JWS header does not match JWK
    #[error("Algorithm in JWS header does not match JWK")]
    AlgorithmMismatch,
    /// Invalid JWS
    #[error("Invalid JWS")]
    InvalidJws,
    /// Unsupported algorithm
    #[error("Unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(String),
    /// Missing crate features
    #[error("Missing features: {0}")]
    MissingFeatures(&'static str),
    #[error("Algorithm `{0}` not implemented")]
    AlgorithmNotImplemented(String),
    #[error("Expected signature length {0} but found {1}")]
    UnexpectedSignatureLength(usize, usize),
    #[error("Invalid signature")]
    InvalidSignature,
}

impl From<InvalidHeader> for Error {
    fn from(value: InvalidHeader) -> Self {
        match value {
            InvalidHeader::Base64(e) => Self::Base64(e),
            InvalidHeader::Json(e) => Self::Json(e),
        }
    }
}

#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for Error {
    fn from(e: ring::error::Unspecified) -> Self {
        ssi_jwk::Error::from(e).into()
    }
}

impl From<Error> for SignatureError {
    fn from(value: Error) -> Self {
        match value {
            Error::AlgorithmMismatch => Self::AlgorithmMismatch,
            Error::AlgorithmNotImplemented(name) => Self::UnsupportedAlgorithm(name),
            Error::UnsupportedAlgorithm(name) => Self::UnsupportedAlgorithm(name),
            other => Self::other(other),
        }
    }
}
