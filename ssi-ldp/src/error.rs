#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Missing Algorithm")]
    MissingAlgorithm,
    #[error("Missing Key")]
    MissingKey,
    #[error("Missing Context")]
    MissingContext,
    #[error("Invalid Context")]
    InvalidContext,
    #[error("Missing Verification Method")]
    MissingVerificationMethod,
    #[error("Missing Proof Signature")]
    MissingProofSignature,
    #[error("Missing JWS Header")]
    MissingJWSHeader,
    #[error("Unsupported Check")]
    UnsupportedCheck,
    #[error("Verification Method Mismatch")]
    VerificationMethodMismatch,
    #[error("Expected Multibase Z prefix (base58)")]
    ExpectedMultibaseZ,
    #[error("A verification method MUST NOT contain multiple verification material properties for the same material.")]
    MultipleKeyMaterial,
    #[error("Unsupported non-DID issuer: {0}")]
    UnsupportedNonDIDIssuer(String),
    #[error("Missing proof purpose")]
    MissingProofPurpose,
    #[error("Linked Data Proof type not implemented")]
    ProofTypeNotImplemented,
    #[error("Unsupported curve")]
    UnsupportedCurve,
    #[error("Missing type")]
    MissingType,
    #[error("Missing verification relationship. Issuer: {0}. Proof purpose: {1:?}. Verification method id: {2}")]
    MissingVerificationRelationship(String, ssi_dids::VerificationRelationship, String),
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
    #[error(transparent)]
    B58(#[from] bs58::decode::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    JsonLd(#[from] ssi_json_ld::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    BlockchainAccountIdParse(#[from] caips::caip10::BlockchainAccountIdParseError),
    #[error(transparent)]
    BlockchainAccountIdVerify(#[from] caips::caip10::BlockchainAccountIdVerifyError),

    #[error(transparent)]
    DecodeTezosPublicKey(#[from] ssi_tzkey::DecodeTezosPkError),
    #[error(transparent)]
    DecodeTezosSignature(#[from] ssi_tzkey::DecodeTezosSignatureError),
    #[error(transparent)]
    EncodeTezosSignedMessage(#[from] ssi_tzkey::EncodeTezosSignedMessageError),
}

impl From<ssi_jwk::Error> for Error {
    fn from(e: ssi_jwk::Error) -> Self {
        Self::JWS(e.into())
    }
}
