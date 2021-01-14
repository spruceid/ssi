use base64::DecodeError as Base64Error;
#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::SignatureError as Ed25519SignatureError;
use iref::Error as IRIError;
use json::Error as JSONError;
use json_ld::Error as JSONLDError;
use json_ld::ErrorCode as JSONLDErrorCode;
use multibase::Error as MultibaseError;
#[cfg(feature = "ring")]
use ring::error::KeyRejected as KeyRejectedError;
#[cfg(feature = "ring")]
use ring::error::Unspecified as RingUnspecified;
#[cfg(feature = "rsa")]
use rsa::errors::Error as RsaError;
use serde_json::Error as SerdeJSONError;
use simple_asn1::ASN1EncodeErr as ASN1EncodeError;
use std::array::TryFromSliceError;
use std::char::CharTryFromError;
use std::fmt;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidSubject,
    InvalidCriticalHeader,
    UnknownCriticalHeader,
    InvalidIssuer,
    NotImplemented,
    AlgorithmNotImplemented,
    ProofTypeNotImplemented,
    MissingAlgorithm,
    MissingIdentifier,
    MissingChosenIssuer,
    ExpectedTerm,
    ExpectedNQuad,
    ExpectedLiteral,
    ExpectedBlankNodeLabel,
    ExpectedIRIRef,
    ExpectedLang,
    AlgorithmMismatch,
    UnsupportedAlgorithm,
    KeyTypeNotImplemented,
    CurveNotImplemented(String),
    MissingKey,
    MissingPrivateKey,
    MissingModulus,
    MissingExponent,
    MissingPrime,
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
    InvalidJWS,
    MissingCredentialSchema,
    UnsupportedProperty,
    UnsupportedKeyType,
    UnsupportedType,
    UnsupportedProofPurpose,
    UnsupportedCheck,
    UnsupportedBlankPredicate,
    TooManyBlankNodes,
    JWTCredentialInPresentation,
    ExpectedUnencodedHeader,
    ResourceNotFound,
    InvalidProofTypeType,
    InvalidKeyLength,
    InconsistentDIDKey,
    RingError,
    ExpectedObject,
    ExpectedArray,
    ExpectedString,
    ExpectedList,
    ExpectedArrayList,
    ExpectedValue,
    MissingGraph,
    MissingActiveProperty,
    MissingActivePropertyEntry,
    // https://w3c.github.io/json-ld-api/#dom-jsonlderrorcode-conflicting-indexes
    ConflictingIndexes,
    ValueObjectLanguageType,
    UnexpectedKeyword,
    UnexpectedIRI,
    ExpectedValueTypeJson,
    UnrecognizedDirection,
    ExpectedStringIndex,
    UnexpectedNestedArray,
    UnexpectedValue,
    UnexpectedList,
    UnexpectedSet,
    ExpectedLangStringType,
    IRIRefNotWellFormed,
    SerializeDouble,
    ExpectedFailure,
    ExpectedOutput(String, String),
    UnknownProcessingMode(String),
    UnknownRdfDirection(String),
    #[cfg(feature = "ring")]
    KeyRejected(KeyRejectedError),
    FromUtf8(FromUtf8Error),
    #[cfg(feature = "rsa")]
    Rsa(RsaError),
    #[cfg(feature = "ed25519-dalek")]
    Ed25519Signature(Ed25519SignatureError),
    ASN1Encode(ASN1EncodeError),
    Base64(Base64Error),
    Multibase(MultibaseError),
    JSON(JSONError),
    SerdeJSON(SerdeJSONError),
    JSONLD(JSONLDErrorCode),
    IRI(IRIError),
    ParseInt(ParseIntError),
    CharTryFrom(CharTryFromError),
    TryFromSlice(TryFromSliceError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidSubject => write!(f, "Invalid subject for JWT"),
            Error::InvalidCriticalHeader => write!(f, "Invalid crit property in JWT header"),
            Error::UnknownCriticalHeader => write!(f, "Unknown critical header name in JWT header"),
            Error::InvalidIssuer => write!(f, "Invalid issuer for JWT"),
            Error::MissingKey => write!(f, "JWT key not found"),
            Error::MissingPrivateKey => write!(f, "Missing private key parametern JWK"),
            Error::MissingModulus => write!(f, "Missing modulus in RSA key"),
            Error::MissingExponent => write!(f, "Missing modulus in RSA key"),
            Error::MissingPrime => write!(f, "Missing prime factor in RSA key"),
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
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::AlgorithmNotImplemented => write!(f, "JWA algorithm not implemented"),
            Error::ProofTypeNotImplemented => write!(f, "Linked Data Proof type not implemented"),
            Error::MissingAlgorithm => write!(f, "Missing algorithm in JWT"),
            Error::MissingIdentifier => write!(f, "Missing identifier"),
            Error::MissingChosenIssuer => write!(f, "Missing chosen issuer"),
            Error::ExpectedTerm => write!(f, "Expected RDF term"),
            Error::ExpectedNQuad => write!(f, "Expected RDF N-Quad"),
            Error::ExpectedLiteral => write!(f, "Expected RDF Literal"),
            Error::ExpectedBlankNodeLabel => write!(f, "Expected RDF blank node label"),
            Error::ExpectedIRIRef => write!(f, "Expected RDF IRI reference"),
            Error::ExpectedLang => write!(f, "Expected RDF language tag"),
            Error::AlgorithmMismatch => write!(f, "Algorithm in JWS header does not match JWK"),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
            Error::KeyTypeNotImplemented => write!(f, "Key type not implemented"),
            Error::CurveNotImplemented(curve) => write!(f, "Curve not implemented: '{:?}'", curve),
            Error::TimeError => write!(f, "Unable to convert date/time"),
            Error::InvalidContext => write!(f, "Invalid context"),
            Error::MissingContext => write!(f, "Missing context"),
            Error::MissingDocumentId => write!(f, "Missing document ID"),
            Error::MissingProofSignature => write!(f, "Missing JWS in proof"),
            Error::ExpiredProof => write!(f, "Expired proof"),
            Error::FutureProof => write!(f, "Proof creation time is in the future"),
            Error::InvalidSignature => write!(f, "Invalid Signature"),
            Error::InvalidJWS => write!(f, "Invalid JWS"),
            Error::InvalidProofPurpose => write!(f, "Invalid proof purpose"),
            Error::InvalidProofDomain => write!(f, "Invalid proof domain"),
            Error::MissingCredentialSchema => write!(f, "Missing credential schema for ZKP"),
            Error::UnsupportedProperty => write!(f, "Unsupported property for LDP"),
            Error::UnsupportedKeyType => write!(f, "Unsupported key type for did:key"),
            Error::TooManyBlankNodes => write!(f, "Multiple blank nodes not supported. Either credential or credential subject must have id property. Presentation must have id property."),
            Error::UnsupportedType => write!(f, "Unsupported type for LDP"),
            Error::UnsupportedProofPurpose => write!(f, "Unsupported proof purpose"),
            Error::UnsupportedCheck => write!(f, "Unsupported check"),
            Error::UnsupportedBlankPredicate => write!(f, "Blank node identifier in predicate is unsupported"),
            Error::JWTCredentialInPresentation => write!(f, "Unsupported JWT VC in VP"),
            Error::ExpectedUnencodedHeader => write!(f, "Expected unencoded JWT header"),
            Error::ResourceNotFound => write!(f, "Resource not found"),
            Error::InvalidProofTypeType => write!(f, "Invalid ProofType type"),
            Error::InvalidKeyLength => write!(f, "Invalid key length"),
            Error::InconsistentDIDKey => write!(f, "Inconsistent DID Key"),
            Error::URI => write!(f, "Invalid URI"),
            Error::RingError => write!(f, "Crypto error"),
            Error::ExpectedObject => write!(f, "Expected object"),
            Error::ExpectedArray => write!(f, "Expected array"),
            Error::ExpectedString => write!(f, "Expected string"),
            Error::ExpectedList => write!(f, "Expected object with @list key"),
            Error::ExpectedArrayList => write!(f, "Expected array in @list"),
            Error::ExpectedValue => write!(f, "Expected object with @value key"),
            Error::MissingGraph => write!(f, "Missing graph"),
            Error::MissingActiveProperty => write!(f, "Missing active property"),
            Error::MissingActivePropertyEntry => write!(f, "Missing active property entry"),
            Error::ConflictingIndexes => write!(f, "Multiple conflicting indexes have been found for the same node."),
            Error::ValueObjectLanguageType => write!(f, "Value object with @type must not contain @language or @direction"),
            Error::UnexpectedKeyword => write!(f, "Unexpected keyword in object"),
            Error::UnexpectedIRI => write!(f, "Unexpected IRI in object"),
            Error::ExpectedValueTypeJson => write!(f, "Value object expected @json @type for array or object value"),
            Error::UnrecognizedDirection => write!(f, "Unrecognized @direction value"),
            Error::ExpectedStringIndex => write!(f, "Expected string value for @index key of value object"),
            Error::UnexpectedNestedArray => write!(f, "Unexpected nested array"),
            Error::UnexpectedValue => write!(f, "Unexpected @value key"),
            Error::UnexpectedList => write!(f, "Unexpected @list key"),
            Error::UnexpectedSet => write!(f, "Unexpected @set key"),
            Error::ExpectedLangStringType => write!(f, "Expected rdf:langString type with language-tagged string literal"),
            Error::IRIRefNotWellFormed => write!(f, "IRI reference not well-formed"),
            Error::SerializeDouble => write!(f, "Unable to serialize double"),
            Error::ExpectedFailure => write!(f, "Expected failure"),
            Error::ExpectedOutput(expected, found) => write!(f, "Expected output '{}', but found '{}'", expected, found),
            Error::UnknownProcessingMode(mode) => write!(f, "Unknown processing mode '{}'", mode),
            Error::UnknownRdfDirection(direction) => write!(f, "Unknown RDF direction '{}'", direction),
            Error::FromUtf8(e) => e.fmt(f),
            Error::TryFromSlice(e) => e.fmt(f),
            #[cfg(feature = "ring")]
            Error::KeyRejected(e) => e.fmt(f),
            #[cfg(feature = "rsa")]
            Error::Rsa(e) => e.fmt(f),
            #[cfg(feature = "ed25519-dalek")]
            Error::Ed25519Signature(e) => e.fmt(f),
            Error::Base64(e) => e.fmt(f),
            Error::Multibase(e) => e.fmt(f),
            Error::ASN1Encode(e) => e.fmt(f),
            Error::JSON(e) => e.fmt(f),
            Error::SerdeJSON(e) => e.fmt(f),
            Error::JSONLD(e) => e.fmt(f),
            Error::IRI(e) => e.fmt(f),
            Error::ParseInt(e) => e.fmt(f),
            Error::CharTryFrom(e) => e.fmt(f),
        }
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

impl From<ASN1EncodeError> for Error {
    fn from(err: ASN1EncodeError) -> Error {
        Error::ASN1Encode(err)
    }
}

impl From<JSONError> for Error {
    fn from(err: JSONError) -> Error {
        Error::JSON(err)
    }
}

impl From<SerdeJSONError> for Error {
    fn from(err: SerdeJSONError) -> Error {
        Error::SerdeJSON(err)
    }
}

impl From<JSONLDError> for Error {
    fn from(err: JSONLDError) -> Error {
        Error::JSONLD(err.code())
    }
}

impl From<IRIError> for Error {
    fn from(err: IRIError) -> Error {
        Error::IRI(err)
    }
}

#[cfg(feature = "ring")]
impl From<KeyRejectedError> for Error {
    fn from(err: KeyRejectedError) -> Error {
        Error::KeyRejected(err)
    }
}

#[cfg(feature = "ring")]
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

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        Error::FromUtf8(err)
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Error {
        Error::ParseInt(err)
    }
}

impl From<CharTryFromError> for Error {
    fn from(err: CharTryFromError) -> Error {
        Error::CharTryFrom(err)
    }
}

#[cfg(feature = "rsa")]
impl From<RsaError> for Error {
    fn from(err: RsaError) -> Error {
        Error::Rsa(err)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl From<Ed25519SignatureError> for Error {
    fn from(err: Ed25519SignatureError) -> Error {
        Error::Ed25519Signature(err)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Error {
        Error::TryFromSlice(err)
    }
}
