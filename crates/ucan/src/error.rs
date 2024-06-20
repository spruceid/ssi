use ssi_verification_methods::InvalidVerificationMethod;

use crate::BlockchainAccountIdError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids_core::resolution::DerefError),
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),
    #[error("Verification method mismatch")]
    VerificationMethodMismatch,
    #[error(transparent)]
    InvalidVerificationMethod(#[from] InvalidVerificationMethod),
    #[error("Missing verification method public key")]
    MissingPublicKey,
    #[error("Invalid verification method blockchain account id: {0}")]
    BlockchainAccountId(#[from] BlockchainAccountIdError),
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
