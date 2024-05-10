use core::fmt;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing signature algorithm")]
    MissingAlgorithm,

    #[error("algorithm mismatch")]
    AlgorithmMismatch,

    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("missing required public key")]
    MissingPublicKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("proof configuration: {0}")]
    ProofConfiguration(String),

    #[error("claims: {0}")]
    Claims(String),

    #[error("missing signer")]
    MissingSigner,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("{0}")]
    Other(String),
}

impl SignatureError {
    pub fn other(e: impl fmt::Display) -> Self {
        Self::Other(e.to_string())
    }
}

// #[derive(Debug, thiserror::Error)]
// pub enum SignatureError {
//     #[error("verification method resolution failed: {0}")]
//     Resolution(#[from] VerificationMethodResolutionError),

//     #[error("missing verification method")]
//     MissingVerificationMethod,

//     #[error("unknown verification method")]
//     UnknownVerificationMethod,

//     #[error("no signer for requested verification method")]
//     MissingSigner,

//     #[error("invalid hash")]
//     InvalidHash,

//     #[error("invalid public key")]
//     InvalidPublicKey,

//     #[error("invalid secret key")]
//     InvalidSecretKey,

//     #[error(transparent)]
//     InvalidVerificationMethod(#[from] InvalidVerificationMethod),

//     #[error("missing public key")]
//     MissingPublicKey,

//     #[error(transparent)]
//     Signer(#[from] ssi_crypto::MessageSignatureError),

//     #[error("invalid received signature")]
//     InvalidSignature,

//     #[error("invalid signature algorithm")]
//     InvalidAlgorithm,

//     #[error("missing signature algorithm")]
//     MissingAlgorithm,
// }

impl From<std::convert::Infallible> for SignatureError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}
