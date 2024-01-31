use thiserror::Error;

/// Error type for `ssi`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    LDP(#[from] ssi_ldp::Error),
    #[error(transparent)]
    URIParse(#[from] ssi_core::uri::URIParseErr),
    #[error("Missing proof")]
    MissingProof,
    #[error("Invalid issuer")]
    InvalidIssuer,
    #[error("Missing issuance date")]
    MissingIssuanceDate,
    #[error("Unable to convert date/time")]
    TimeError,
    /// Verification method id does not match JWK id
    #[error("Verification method id does not match JWK id. VM id: {0}, JWK key id: {1}")]
    KeyIdVMMismatch(String, String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
