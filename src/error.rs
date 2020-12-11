use base64::DecodeError as Base64Error;
use iref::Error as IRIError;
use json::Error as JSONError;
use json_ld::Error as JSONLDError;
use json_ld::ErrorCode as JSONLDErrorCode;
use jsonwebtoken::errors::Error as JWTError;
use multibase::Error as MultibaseError;
use ring::error::KeyRejected as KeyRejectedError;
use ring::error::Unspecified as RingUnspecified;
use serde_json::Error as SerdeJSONError;
use std::char::CharTryFromError;
use std::fmt;
use std::num::ParseIntError;

#[derive(Debug)]
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
    KeyRejected(KeyRejectedError),
    JWT(JWTError),
    Base64(Base64Error),
    Multibase(MultibaseError),
    JSON(JSONError),
    SerdeJSON(SerdeJSONError),
    JSONLD(JSONLDErrorCode),
    IRI(IRIError),
    ParseInt(ParseIntError),
    CharTryFrom(CharTryFromError),

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
            Error::SerializeDouble => write!(f, "Unable ot serialize double"),
            Error::KeyRejected(e) => e.fmt(f),
            Error::Base64(e) => e.fmt(f),
            Error::Multibase(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
            Error::JSON(e) => e.fmt(f),
            Error::SerdeJSON(e) => e.fmt(f),
            Error::JSONLD(e) => e.fmt(f),
            Error::IRI(e) => e.fmt(f),
            Error::ParseInt(e) => e.fmt(f),
            Error::CharTryFrom(e) => e.fmt(f),
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
