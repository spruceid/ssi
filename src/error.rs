use crate::caip10::BlockchainAccountIdParseError;
use crate::caip10::BlockchainAccountIdVerifyError;
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedDataConstructionError;
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedDataHashError;
use crate::json_ld;
use base64::DecodeError as Base64Error;
#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::ed25519::Error as ED25519Error;
use iref::Error as IRIError;
use json::Error as JSONError;
use json_ld::Error as JSONLDError;
use json_ld::ErrorCode as JSONLDErrorCode;
#[cfg(feature = "k256")]
use k256::ecdsa::Error as Secp256k1Error;
use multibase::Error as MultibaseError;
#[cfg(feature = "p256")]
use p256::ecdsa::Error as Secp256r1Error;
#[cfg(feature = "ring")]
use ring::error::KeyRejected as KeyRejectedError;
#[cfg(feature = "ring")]
use ring::error::Unspecified as RingUnspecified;
#[cfg(feature = "rsa")]
use rsa::errors::Error as RsaError;
use serde_json::Error as SerdeJSONError;
use serde_urlencoded::de::Error as SerdeUrlEncodedError;
use simple_asn1::ASN1EncodeErr as ASN1EncodeError;
use std::array::TryFromSliceError;
use std::char::CharTryFromError;
use std::fmt;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
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
    MissingCurve,
    MissingPoint,
    MissingIdentifier,
    MissingChosenIssuer,
    ExpectedTerm,
    ExpectedNQuad,
    ExpectedLiteral,
    ExpectedBlankNodeLabel,
    ExpectedIRIRef,
    ExpectedLang,
    AlgorithmMismatch,
    KeyMismatch,
    VerificationMethodMismatch,
    UnsupportedAlgorithm,
    UnsupportedMultipleVMs,
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
    MissingAccountId,
    MissingVerificationMethod,
    Key,
    Secp256k1Parse(String),
    MultipleKeyMaterial,
    TimeError,
    URI,
    DIDURL,
    DIDURLDereference(String),
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
    MissingJWSHeader,
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
    ResourceNotFound(String),
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
    RepresentationNotSupported,
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
    ED25519(ED25519Error),
    #[cfg(feature = "k256")]
    Secp256k1(Secp256k1Error),
    #[cfg(feature = "p256")]
    Secp256r1(Secp256r1Error),
    ASN1Encode(ASN1EncodeError),
    Base64(Base64Error),
    Multibase(MultibaseError),
    JSON(JSONError),
    SerdeJSON(SerdeJSONError),
    SerdeUrlEncoded(SerdeUrlEncodedError),
    JSONLD(JSONLDErrorCode),
    IRI(IRIError),
    ParseInt(ParseIntError),
    CharTryFrom(CharTryFromError),
    TryFromSlice(TryFromSliceError),
    BlockchainAccountIdParse(BlockchainAccountIdParseError),
    BlockchainAccountIdVerify(BlockchainAccountIdVerifyError),
    #[cfg(feature = "keccak-hash")]
    TypedDataConstruction(TypedDataConstructionError),
    #[cfg(feature = "keccak-hash")]
    TypedDataHash(TypedDataHashError),
    FromHex(hex::FromHexError),
    Base58(bs58::decode::Error),
    HexString,
    SignaturePrefix,
    KeyPrefix,
    P256KeyLength(usize),
    ECEncodingError,
    ECDecompress,
    #[cfg(feature = "k256")]
    K256EC(k256::elliptic_curve::Error),
    #[cfg(feature = "p256")]
    P256EC(p256::elliptic_curve::Error),
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
            Error::MissingAccountId => write!(f, "Missing account id"),
            Error::MissingVerificationMethod => write!(f, "Missing verificationMethod"),
            Error::MissingCredential => write!(f, "Verifiable credential not found in JWT"),
            Error::Key => write!(f, "problem with JWT key"),
            Error::Secp256k1Parse(s) => write!(f, "problem parsing secp256k1 key: {}", s),
            Error::MultipleKeyMaterial => write!(f, "A verification method MUST NOT contain multiple verification material properties for the same material."),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::AlgorithmNotImplemented => write!(f, "JWA algorithm not implemented"),
            Error::ProofTypeNotImplemented => write!(f, "Linked Data Proof type not implemented"),
            Error::MissingAlgorithm => write!(f, "Missing algorithm in JWT"),
            Error::MissingCurve => write!(f, "Missing curve in JWK"),
            Error::MissingPoint => write!(f, "Missing elliptic curve point in JWK"),
            Error::MissingIdentifier => write!(f, "Missing identifier"),
            Error::MissingChosenIssuer => write!(f, "Missing chosen issuer"),
            Error::ExpectedTerm => write!(f, "Expected RDF term"),
            Error::ExpectedNQuad => write!(f, "Expected RDF N-Quad"),
            Error::ExpectedLiteral => write!(f, "Expected RDF Literal"),
            Error::ExpectedBlankNodeLabel => write!(f, "Expected RDF blank node label"),
            Error::ExpectedIRIRef => write!(f, "Expected RDF IRI reference"),
            Error::ExpectedLang => write!(f, "Expected RDF language tag"),
            Error::AlgorithmMismatch => write!(f, "Algorithm in JWS header does not match JWK"),
            Error::KeyMismatch => write!(f, "Key mismatch"),
            Error::VerificationMethodMismatch => write!(f, "Verification method mismatch"),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
            Error::UnsupportedMultipleVMs => write!(f, "Unsupported multiple verification methods"),
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
            Error::MissingJWSHeader => write!(f, "Missing JWS Header"),
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
            Error::ResourceNotFound(id) => write!(f, "Resource not found: {}", id),
            Error::InvalidProofTypeType => write!(f, "Invalid ProofType type"),
            Error::InvalidKeyLength => write!(f, "Invalid key length"),
            Error::InconsistentDIDKey => write!(f, "Inconsistent DID Key"),
            Error::DIDURL => write!(f, "Invalid DID URL"),
            Error::DIDURLDereference(error) => write!(f, "Unable to dereference DID URL: {}", error),
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
            Error::RepresentationNotSupported => write!(f, "RepresentationNotSupported"),
            Error::ExpectedLangStringType => write!(f, "Expected rdf:langString type with language-tagged string literal"),
            Error::IRIRefNotWellFormed => write!(f, "IRI reference not well-formed"),
            Error::SerializeDouble => write!(f, "Unable to serialize double"),
            Error::ExpectedFailure => write!(f, "Expected failure"),
            Error::ExpectedOutput(expected, found) => write!(f, "Expected output '{}', but found '{}'", expected, found),
            Error::UnknownProcessingMode(mode) => write!(f, "Unknown processing mode '{}'", mode),
            Error::UnknownRdfDirection(direction) => write!(f, "Unknown RDF direction '{}'", direction),
            Error::HexString => write!(f, "Expected string beginning with '0x'"),
            Error::SignaturePrefix => write!(f, "Unknown signature prefix"),
            Error::KeyPrefix => write!(f, "Unknown key prefix"),
            Error::FromUtf8(e) => e.fmt(f),
            Error::TryFromSlice(e) => e.fmt(f),
            #[cfg(feature = "ring")]
            Error::KeyRejected(e) => e.fmt(f),
            #[cfg(feature = "rsa")]
            Error::Rsa(e) => e.fmt(f),
            #[cfg(feature = "ed25519-dalek")]
            Error::ED25519(e) => e.fmt(f),
            #[cfg(feature = "k256")]
            Error::Secp256k1(e) => e.fmt(f),
            #[cfg(feature = "p256")]
            Error::Secp256r1(e) => e.fmt(f),
            Error::Base64(e) => e.fmt(f),
            Error::Multibase(e) => e.fmt(f),
            Error::ASN1Encode(e) => e.fmt(f),
            Error::JSON(e) => e.fmt(f),
            Error::SerdeJSON(e) => e.fmt(f),
            Error::SerdeUrlEncoded(e) => e.fmt(f),
            Error::JSONLD(e) => e.fmt(f),
            Error::IRI(e) => e.fmt(f),
            Error::ParseInt(e) => e.fmt(f),
            Error::CharTryFrom(e) => e.fmt(f),
            Error::BlockchainAccountIdParse(e) => e.fmt(f),
            Error::BlockchainAccountIdVerify(e) => e.fmt(f),
            #[cfg(feature = "keccak-hash")]
            Error::TypedDataConstruction(e) => e.fmt(f),
            #[cfg(feature = "keccak-hash")]
            Error::TypedDataHash(e) => e.fmt(f),
            Error::FromHex(e) => e.fmt(f),
            Error::Base58(e) => e.fmt(f),
            #[cfg(feature = "k256")]
            Error::K256EC(e) => e.fmt(f),
            #[cfg(feature = "p256")]
            Error::P256EC(e) => e.fmt(f),
            Error::P256KeyLength(len) => write!(f, "Expected 64 byte uncompressed key or 33 bytes compressed key but found length: {}", len),
            Error::ECEncodingError => write!(f, "Unable to encode EC key"),
            Error::ECDecompress => write!(f, "Unable to decompress elliptic curve"),
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

impl From<SerdeUrlEncodedError> for Error {
    fn from(err: SerdeUrlEncodedError) -> Error {
        Error::SerdeUrlEncoded(err)
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

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Error {
        Error::TryFromSlice(err)
    }
}

impl From<BlockchainAccountIdParseError> for Error {
    fn from(err: BlockchainAccountIdParseError) -> Error {
        Error::BlockchainAccountIdParse(err)
    }
}

impl From<BlockchainAccountIdVerifyError> for Error {
    fn from(err: BlockchainAccountIdVerifyError) -> Error {
        Error::BlockchainAccountIdVerify(err)
    }
}

#[cfg(feature = "keccak-hash")]
impl From<TypedDataConstructionError> for Error {
    fn from(err: TypedDataConstructionError) -> Error {
        Error::TypedDataConstruction(err)
    }
}

#[cfg(feature = "keccak-hash")]
impl From<TypedDataHashError> for Error {
    fn from(err: TypedDataHashError) -> Error {
        Error::TypedDataHash(err)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Error {
        Error::FromHex(err)
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(err: bs58::decode::Error) -> Error {
        Error::Base58(err)
    }
}

#[cfg(feature = "k256")]
impl From<Secp256k1Error> for Error {
    fn from(err: Secp256k1Error) -> Error {
        Error::Secp256k1(err)
    }
}

// Conflicting implementations as the underlying types are the same
#[cfg(all(feature = "p256", not(feature = "k256")))]
impl From<Secp256r1Error> for Error {
    fn from(err: Secp256r1Error) -> Error {
        Error::Secp256r1(err)
    }
}

#[cfg(feature = "k256")]
impl From<k256::elliptic_curve::Error> for Error {
    fn from(err: k256::elliptic_curve::Error) -> Error {
        Error::K256EC(err)
    }
}

// Conflicting implementations as the underlying types are the same
#[cfg(all(feature = "p256", not(feature = "k256")))]
impl From<p256::elliptic_curve::Error> for Error {
    fn from(err: p256::elliptic_curve::Error) -> Error {
        Error::P256EC(err)
    }
}

#[cfg(all(
    feature = "ed25519-dalek",
    not(feature = "k256"),
    not(feature = "p256")
))]
impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Error {
        Error::ED25519(err)
    }
}
