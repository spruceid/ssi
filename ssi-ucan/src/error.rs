#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),
    #[error("Verification method mismatch")]
    VerificationMethodMismatch,
    #[error("Header contains invalid fields")]
    InvalidHeaderEntries,
    #[error("Incorrect Signature Length")]
    IncorrectSignatureLength,
    #[error("Failed to encode signature: {0}")]
    SignatureEncodingError(#[from] varsig::SerError<std::convert::Infallible>),
    #[error("Failed to decode signature: {0}")]
    SignatureDecodingError(#[from] varsig::DeserError<varsig::common::webauthn::Error>),
    #[error("Challenge Mismatch")]
    ChallengeMismatch,
    #[error("Invalid DID URL")]
    DIDURL,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Caip10Parse(#[from] ssi_caips::caip10::BlockchainAccountIdParseError),
    #[error(transparent)]
    Caip10Verify(#[from] ssi_caips::caip10::BlockchainAccountIdVerifyError),
    #[error("Unable to infer algorithm")]
    AlgUnknown,
}
