use crate::proof::ProofInconsistency;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Missing Algorithm")]
    MissingAlgorithm,
    #[error("Missing Key")]
    MissingKey,
    #[error("Missing Context")]
    MissingContext,
    #[error("Invalid context")]
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
    #[error("Linked Data Proof type not implemented or not enabled by feature")]
    ProofTypeNotSupported,
    #[error("Unsupported curve")]
    UnsupportedCurve,
    #[error("Missing type")]
    MissingType,
    #[error("Missing verification relationship. Issuer: {0}. Proof purpose: {1:?}. Verification method id: {2}")]
    MissingVerificationRelationship(String, ssi_dids::VerificationRelationship, String),
    #[error("Invalid Hex String")]
    HexString,
    /// Error decoding hex data
    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
    #[error(transparent)]
    B58(#[from] bs58::decode::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    ToRdfError(#[from] Box<ssi_json_ld::ToRdfError>),
    #[error(transparent)]
    InvalidJsonLdContext(#[from] ssi_json_ld::ContextError),
    #[error("Expected a JSON object")]
    ExpectedJsonObject,
    #[error(transparent)]
    BlockchainAccountIdParse(#[from] ssi_caips::caip10::BlockchainAccountIdParseError),
    #[error(transparent)]
    BlockchainAccountIdVerify(#[from] ssi_caips::caip10::BlockchainAccountIdVerifyError),
    #[cfg(feature = "tezos")]
    #[error(transparent)]
    DecodeTezosPublicKey(#[from] ssi_tzkey::DecodeTezosPkError),
    #[cfg(feature = "tezos")]
    #[error(transparent)]
    DecodeTezosSignature(#[from] ssi_tzkey::DecodeTezosSignatureError),
    #[cfg(feature = "tezos")]
    #[error(transparent)]
    EncodeTezosSignedMessage(#[from] ssi_tzkey::EncodeTezosSignedMessageError),
    #[cfg(feature = "eip")]
    #[error(transparent)]
    Eip712Hash(#[from] crate::eip712::TypedDataHashError),
    #[cfg(feature = "eip")]
    #[error(transparent)]
    Eip712Json(#[from] crate::eip712::TypedDataConstructionJSONError),
    #[cfg(feature = "eip")]
    #[error(transparent)]
    Eip712Construction(#[from] crate::eip712::TypedDataConstructionError),
    #[cfg(feature = "aleo")]
    #[error(transparent)]
    AleoSign(#[from] ssi_jwk::aleo::AleoSignError),
    #[cfg(feature = "aleo")]
    #[error(transparent)]
    AleoVerify(#[from] ssi_jwk::aleo::AleoVerifyError),
    #[cfg(feature = "aleo")]
    #[error("Expected Aleo network '{0}' but found '{1}'")]
    UnexpectedAleoNetwork(String, String),
    #[error("Expected CAIP-2 namespace '{0}' but found '{1}'")]
    UnexpectedCAIP2Namespace(String, String),
    #[error(transparent)]
    InconsistentProof(#[from] Box<ProofInconsistency>),
    #[error("Unsupported cryptosuite")]
    UnsupportedCryptosuite,
    #[error("Invalid cryptosuite type")]
    InvalidCryptosuiteType,
    #[error("Invalid cryptosuite, expected {0} but key supports {1}")]
    UnexpectedCryptosuite(String, String),
}

impl From<ssi_jwk::Error> for Error {
    fn from(e: ssi_jwk::Error) -> Self {
        Self::JWS(e.into())
    }
}
