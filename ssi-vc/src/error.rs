use thiserror::Error;

/// Error type for `ssi-vc`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    LDP(#[from] ssi_ldp::Error),
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    URIParse(#[from] ssi_core::uri::URIParseErr),
    #[error("Missing proof")]
    MissingProof,
    #[error("Missing credential schema")]
    MissingCredentialSchema,
    #[error("Missing credential")]
    MissingCredential,
    #[error("Missing presentation")]
    MissingPresentation,
    #[error("Invalid issuer")]
    InvalidIssuer,
    #[error("Missing holder property")]
    MissingHolder,
    #[error("Unsupported Holder Binding")]
    UnsupportedHolderBinding,
    #[error(transparent)]
    HolderBindingVerification(#[from] crate::cacao::Error),
    #[error("Missing issuance date")]
    MissingIssuanceDate,
    #[error("Missing type VerifiableCredential")]
    MissingTypeVerifiableCredential,
    #[error("Missing type VerifiablePresentation")]
    MissingTypeVerifiablePresentation,
    #[error("Invalid subject")]
    InvalidSubject,
    #[error("Unable to convert date/time")]
    TimeError,
    #[error(transparent)]
    DateConvertion(#[from] ssi_jwt::NumericDateConversionError),
    #[error("Empty credential subject")]
    EmptyCredentialSubject,
    /// Verification method id does not match JWK id
    #[error("Verification method id does not match JWK id. VM id: {0}, JWK key id: {1}")]
    KeyIdVMMismatch(String, String),
    /// Linked data proof option unencodable as JWT claim
    #[error("Linked data proof option unencodable as JWT claim: {0}")]
    UnencodableOptionClaim(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
