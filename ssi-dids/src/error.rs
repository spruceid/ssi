//! Error types for `ssi` crate
use multibase::Error as MultibaseError;
use serde_json::Error as SerdeJSONError;
use serde_urlencoded::de::Error as SerdeUrlEncodedError;
use ssi_caips::caip10::{BlockchainAccountIdParseError, BlockchainAccountIdVerifyError};
use thiserror::Error;

/// Error type for `ssi`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Key mismatch
    #[error("Key mismatch")]
    KeyMismatch,
    /// JWT key not found
    #[error("JWT key not found")]
    MissingKey,
    /// A verification method MUST NOT contain multiple verification material properties for the same material. (DID Core)
    #[error("A verification method MUST NOT contain multiple verification material properties for the same material. (DID Core)")]
    MultipleKeyMaterial,
    /// Invalid DID URL
    #[error("Invalid DID URL")]
    DIDURL,
    /// Unable to dereference DID URL
    #[error("Unable to dereference DID URL: {0}")]
    DIDURLDereference(String),
    /// Unexpected DID fragment
    #[error("Unexpected DID fragment")]
    UnexpectedDIDFragment,
    /// Invalid context
    #[error("Invalid context")]
    InvalidContext,
    /// DID controller limit exceeded
    #[error("DID controller limit exceeded")]
    ControllerLimit,
    /// Missing context
    #[error("Missing context")]
    MissingContext,
    /// Missing document ID
    #[error("Missing document ID")]
    MissingDocumentId,
    /// Expected object
    #[error("Expected object")]
    ExpectedObject,
    /// Unsupported verification relationship
    #[error("Unsupported verification relationship")]
    UnsupportedVerificationRelationship,
    /// Resource not found
    #[error("Resource not found")]
    ResourceNotFound(String),
    /// Expected string for publicKeyMultibase
    #[error("Expected string for publicKeyMultibase")]
    ExpectedStringPublicKeyMultibase,
    /// [`representationNotSupported`](https://www.w3.org/TR/did-spec-registries/#representationnotsupported) DID resolution error
    #[error("RepresentationNotSupported")]
    RepresentationNotSupported,
    /// Error parsing or producing multibase
    #[error(transparent)]
    Multibase(#[from] MultibaseError),
    /// Error from `serde_json` crate
    #[error(transparent)]
    SerdeJSON(#[from] SerdeJSONError),
    /// Error from `serde_urlencoded` crate
    #[error(transparent)]
    SerdeUrlEncoded(#[from] SerdeUrlEncodedError),
    /// Error parsing CAIP-10 blockchain account id
    #[error(transparent)]
    BlockchainAccountIdParse(#[from] BlockchainAccountIdParseError),
    /// Error verifying CAIP-10 blockchain account id against a public key
    #[error(transparent)]
    BlockchainAccountIdVerify(#[from] BlockchainAccountIdVerifyError),
    /// Error decoding hex data
    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),
    /// Error decoding Base58 data
    #[error(transparent)]
    Base58(#[from] bs58::decode::Error),
    /// Expected string beginning with '0x'
    #[error("Expected string beginning with '0x'")]
    HexString,
    /// Unable to resolve DID
    #[error("Unable to resolve: {0}")]
    UnableToResolve(String),
    /// JWK error
    #[error(transparent)]
    JWK(#[from] ssi_jwk::Error),
}

impl From<Error> for String {
    fn from(err: Error) -> String {
        err.to_string()
    }
}
