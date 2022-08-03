#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    JWK(#[from] ssi_jwk::Error),
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
    InvalidJWS,
    /// Unsupported algorithm
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    /// Missing crate features
    #[error("Missing features: {0}")]
    MissingFeatures(&'static str),
}
