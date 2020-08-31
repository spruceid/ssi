// use std::error::Error as StdError;
use base64::DecodeError as Base64Error;
use jsonwebtoken::errors::Error as JWTError;
use serde_json::Error as JSONError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    InvalidSubject,
    InvalidIssuer,
    AlgorithmNotImplemented,
    KeyTypeNotImplemented,
    MissingKey,
    MissingCredential,
    MissingKeyParameters,
    MissingProof,
    MissingIssuanceDate,
    MissingTypeVerifiableCredential,
    MissingTypeVerifiablePresentation,
    MissingIssuer,
    Key,
    TimeError,
    URI,
    InvalidContext,
    MissingContext,
    MissingCredentialSchema,
    JWT(JWTError),
    Base64(Base64Error),
    JSON(JSONError),

    #[doc(hidden)]
    __Nonexhaustive,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidSubject => write!(f, "Invalid subject for JWT"),
            Error::InvalidIssuer => write!(f, "Invalid issuer for JWT"),
            Error::MissingKey => write!(f, "JWT key not found"),
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
            Error::MissingCredential => write!(f, "Verifiable credential not found in JWT"),
            Error::Key => write!(f, "problem with JWT key"),
            Error::AlgorithmNotImplemented => write!(f, "JWA algorithm not implemented"),
            Error::KeyTypeNotImplemented => write!(f, "key type not implemented"),
            Error::TimeError => write!(f, "Unable to convert date/time"),
            Error::InvalidContext => write!(f, "Invalid context"),
            Error::MissingContext => write!(f, "Missing context"),
            Error::MissingCredentialSchema => write!(f, "Missing credential schema for ZKP"),
            Error::URI => write!(f, "Invalid URI"),
            Error::Base64(e) => e.fmt(f),
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

impl From<JSONError> for Error {
    fn from(err: JSONError) -> Error {
        Error::JSON(err)
    }
}
