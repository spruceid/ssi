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
    #[error("Missing UCAN field, expected: '{0}'")]
    MissingUCANHeaderField(&'static str),
    #[error("Invalid DID URL")]
    DIDURL,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Caip10Parse(#[from] ssi_caips::caip10::BlockchainAccountIdParseError),
    #[error(transparent)]
    Caip10Verify(#[from] ssi_caips::caip10::BlockchainAccountIdVerifyError),
}
