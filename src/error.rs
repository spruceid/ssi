use base64::DecodeError as Base64Error;
use jsonwebtoken::errors::Error as JWTError;
use multibase::Error as MultibaseError;
use ring::error::KeyRejected as KeyRejectedError;
use ring::error::Unspecified as RingUnspecified;
use serde_json::Error as JSONError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    InvalidSubject,
    InvalidCriticalHeader,
    UnknownCriticalHeader,
    InvalidIssuer,
    AlgorithmNotImplemented,
    ProofTypeNotImplemented,
    MissingAlgorithm,
    KeyTypeNotImplemented,
    MissingKey,
    MissingModulus,
    MissingExponent,
    MissingCredential,
    MissingKeyParameters,
    MissingProof,
    MissingIssuanceDate,
    MissingTypeVerifiableCredential,
    MissingTypeVerifiablePresentation,
    MissingIssuer,
    MissingVerificationMethod,
    Key,
    TimeError,
    URI,
    InvalidContext,
    MissingContext,
    MissingDocumentId,
    MissingProofSignature,
    ExpiredProof,
    FutureProof,
    InvalidProofPurpose,
    InvalidProofDomain,
    InvalidSignature,
    MissingCredentialSchema,
    UnsupportedProperty,
    UnsupportedKeyType,
    UnsupportedType,
    UnsupportedProofPurpose,
    TooManyBlankNodes,
    JWTCredentialInPresentation,
    ExpectedUnencodedHeader,
    ResourceNotFound,
    InvalidProofTypeType,
    InvalidKeyLength,
    RingError,
    KeyRejected(KeyRejectedError),
    JWT(JWTError),
    Base64(Base64Error),
    Multibase(MultibaseError),
    JSON(JSONError),

    #[doc(hidden)]
    __Nonexhaustive,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidSubject => write!(f, "Invalid subject for JWT"),
            Error::InvalidCriticalHeader => write!(f, "Invalid crit property in JWT header"),
            Error::UnknownCriticalHeader => write!(f, "Unknown critical header name in JWT header"),
            Error::InvalidIssuer => write!(f, "Invalid issuer for JWT"),
            Error::MissingKey => write!(f, "JWT key not found"),
            Error::MissingModulus => write!(f, "Missing modulus in RSA key"),
            Error::MissingExponent => write!(f, "Missing modulus in RSA key"),
            Error::MissingKeyParameters => write!(f, "JWT key parameters not found"),
            Error::MissingProof => write!(f, "Missing proof property"),
            Error::MissingIssuanceDate => write!(f, "Missing issuance date"),
            Error::MissingTypeVerifiableCredential => {
                write!(f, "Missing type VerifiableCredential")
            }
            Error::MissingTypeVerifiablePresentation => {
                write!(f, "Missing type VerifiablePresentation")
            }
            Error::MissingIssuer => write!(f, "Missing issuer property"),
            Error::MissingVerificationMethod => write!(f, "Missing proof verificationMethod"),
            Error::MissingCredential => write!(f, "Verifiable credential not found in JWT"),
            Error::Key => write!(f, "problem with JWT key"),
            Error::AlgorithmNotImplemented => write!(f, "JWA algorithm not implemented"),
            Error::ProofTypeNotImplemented => write!(f, "Linked Data Proof type not implemented"),
            Error::MissingAlgorithm => write!(f, "Missing algorithm in JWT"),
            Error::KeyTypeNotImplemented => write!(f, "key type not implemented"),
            Error::TimeError => write!(f, "Unable to convert date/time"),
            Error::InvalidContext => write!(f, "Invalid context"),
            Error::MissingContext => write!(f, "Missing context"),
            Error::MissingDocumentId => write!(f, "Missing document ID"),
            Error::MissingProofSignature => write!(f, "Missing JWS in proof"),
            Error::ExpiredProof => write!(f, "Expired proof"),
            Error::FutureProof => write!(f, "Proof creation time is in the future"),
            Error::InvalidSignature => write!(f, "Invalid JWS"),
            Error::InvalidProofPurpose => write!(f, "Invalid proof purpose"),
            Error::InvalidProofDomain => write!(f, "Invalid proof domain"),
            Error::MissingCredentialSchema => write!(f, "Missing credential schema for ZKP"),
            Error::UnsupportedProperty => write!(f, "Unsupported property for LDP"),
            Error::UnsupportedKeyType => write!(f, "Unsupported key type for did:key"),
            Error::TooManyBlankNodes => write!(f, "Multiple blank nodes not supported. Either credential or credential subject must have id property. Presentation must have id property."),
            Error::UnsupportedType => write!(f, "Unsupported type for LDP"),
            Error::UnsupportedProofPurpose => write!(f, "Unsupported proof purpose"),
            Error::JWTCredentialInPresentation => write!(f, "Unsupported JWT VC in VP"),
            Error::ExpectedUnencodedHeader => write!(f, "Expected unencoded JWT header"),
            Error::ResourceNotFound => write!(f, "Resource not found"),
            Error::InvalidProofTypeType => write!(f, "Invalid ProofType type"),
            Error::InvalidKeyLength => write!(f, "Invalid key length"),
            Error::URI => write!(f, "Invalid URI"),
            Error::RingError => write!(f, "Crypto error"),
            Error::KeyRejected(e) => e.fmt(f),
            Error::Base64(e) => e.fmt(f),
            Error::Multibase(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
            Error::JSON(e) => e.fmt(f),
            _ => unreachable!(),
        }
    }
}

impl From<JWTError> for Error {
    fn from(err: JWTError) -> Error {
        Error::JWT(err)
    }
}

impl From<Base64Error> for Error {
    fn from(err: Base64Error) -> Error {
        Error::Base64(err)
    }
}

impl From<MultibaseError> for Error {
    fn from(err: MultibaseError) -> Error {
        Error::Multibase(err)
    }
}

impl From<JSONError> for Error {
    fn from(err: JSONError) -> Error {
        Error::JSON(err)
    }
}

impl From<KeyRejectedError> for Error {
    fn from(err: KeyRejectedError) -> Error {
        Error::KeyRejected(err)
    }
}

impl From<RingUnspecified> for Error {
    fn from(_: RingUnspecified) -> Error {
        Error::RingError
    }
}

impl From<Error> for String {
    fn from(err: Error) -> String {
        format!("{}", err)
    }
}
