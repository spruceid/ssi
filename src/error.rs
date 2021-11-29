//! Error types for `ssi` crate
#[cfg(feature = "aleosig")]
use crate::aleo::{AleoGeneratePrivateKeyError, AleoSignError, AleoVerifyError};
use crate::caip10::BlockchainAccountIdParseError;
use crate::caip10::BlockchainAccountIdVerifyError;
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedDataConstructionError;
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedDataConstructionJSONError;
#[cfg(feature = "keccak-hash")]
use crate::eip712::TypedDataHashError;
use crate::tzkey::{DecodeTezosSignatureError, EncodeTezosSignedMessageError};
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

/// Error type for `ssi`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Invalid subject for JWT VC
    InvalidSubject,
    /// Invalid `crit` property in JWT header
    InvalidCriticalHeader,
    /// Unknown `crit` header name in JWT header
    UnknownCriticalHeader,
    /// Invalid issuer for JWT
    InvalidIssuer,
    /// Functionality not implemented
    NotImplemented,
    /// JWA algorithm not implemented
    AlgorithmNotImplemented,
    /// Linked Data Proof type not implemented
    ProofTypeNotImplemented,
    /// Missing algorithm in JWT
    MissingAlgorithm,
    /// Missing curve in JWK
    MissingCurve,
    /// Missing elliptic curve point in JWK
    MissingPoint,
    /// Missing key value for symmetric key
    MissingKeyValue,
    /// Missing identifier
    MissingIdentifier,
    /// Missing chosen issuer
    MissingChosenIssuer,
    /// Expected RDF term
    ExpectedTerm,
    /// Expected RDF N-Quad
    ExpectedNQuad,
    /// Expected RDF Literal
    ExpectedLiteral,
    /// Expected RDF blank node label
    ExpectedBlankNodeLabel,
    /// Expected RDF IRI reference
    ExpectedIRIRef,
    /// Expected RDF language tag
    ExpectedLang,
    /// Algorithm in JWS header does not match JWK
    AlgorithmMismatch,
    /// Verification method id does not match JWK id
    KeyIdVMMismatch(String, String),
    /// RDF statement object does not match value
    ObjectMismatch(String, String, String),
    /// Missing RDF statement object
    ExpectedObjectForPredicate(String, String),
    /// Unexpected RDF statement object
    UnexpectedObjectForPredicate(String, String),
    /// Missing type
    MissingType,
    /// Missing RDF statement
    MissingStatement,
    /// Unexpected end of list
    UnexpectedEndOfList,
    /// List item mismatch
    ListItemMismatch(String, String),
    /// Expected end of list
    ExpectedEndOfList,
    /// Expected rest of list
    ExpectedRestOfList,
    /// Expected list value
    ExpectedListValue,
    /// Unexpected triple
    UnexpectedTriple(crate::rdf::Triple),
    /// Key mismatch
    KeyMismatch,
    /// Verification method mismatch
    VerificationMethodMismatch,
    /// Unsupported algorithm
    UnsupportedAlgorithm,
    /// Unsupported curve
    UnsupportedCurve,
    /// Unsupported multiple verification methods
    UnsupportedMultipleVMs,
    /// Key type not implemented
    KeyTypeNotImplemented,
    /// Unsupported non-DID issuer
    UnsupportedNonDIDIssuer(String),
    /// Curve not implemented
    CurveNotImplemented(String),
    /// JWT key not found
    MissingKey,
    /// Missing private key parametern JWK
    MissingPrivateKey,
    /// Missing modulus in RSA key
    MissingModulus,
    /// Missing exponent in RSA key
    MissingExponent,
    /// Missing prime factor in RSA key
    MissingPrime,
    /// Verifiable credential not found in JWT
    MissingCredential,
    /// Verifiable presentation not found in JWT
    MissingPresentation,
    /// JWT key parameters not found
    MissingKeyParameters,
    /// Missing proof property
    MissingProof,
    /// Missing issuance date
    MissingIssuanceDate,
    /// Missing type VerifiableCredential
    MissingTypeVerifiableCredential,
    /// Missing type VerifiablePresentation
    MissingTypeVerifiablePresentation,
    /// Missing issuer property
    MissingIssuer,
    /// Missing account id
    MissingAccountId,
    /// Missing verificationMethod
    MissingVerificationMethod,
    /// Missing verification relationship
    MissingVerificationRelationship(String, crate::vc::ProofPurpose, String),
    /// Problem with JWT key
    Key,
    /// Problem parsing Secp256k1 key
    Secp256k1Parse(String),
    /// Problem parsing Secp256r1 key
    Secp256r1Parse(String),
    /// A verification method MUST NOT contain multiple verification material properties for the same material. (DID Core)
    MultipleKeyMaterial,
    /// Unable to convert date/time
    TimeError,
    /// Invalid URI
    URI,
    /// Invalid DID URL
    DIDURL,
    /// Unable to dereference DID URL
    DIDURLDereference(String),
    /// Unexpected DID fragment
    UnexpectedDIDFragment,
    /// Invalid context
    InvalidContext,
    /// DID controller limit exceeded
    ControllerLimit,
    /// Missing context
    MissingContext,
    /// Missing document ID
    MissingDocumentId,
    /// Missing JWS in proof
    MissingProofSignature,
    /// Expired proof
    ExpiredProof,
    /// Proof creation time is in the future
    FutureProof,
    /// Invalid proof domain
    InvalidProofPurpose,
    /// Missing proof purpose
    MissingProofPurpose,
    /// Invalid proof domain
    InvalidProofDomain,
    /// Invalid Signature (in proof)
    InvalidSignature,
    /// Signature length did not match expected length.
    UnexpectedSignatureLength(usize, usize),
    /// Invalid JWS
    InvalidJWS,
    /// Missing JWS Header
    MissingJWSHeader,
    /// Missing credential schema for ZKP
    MissingCredentialSchema,
    /// Unsupported property for linked data proof
    UnsupportedProperty,
    /// Unsupported key type
    UnsupportedKeyType,
    /// Unsupported type for linked data proof
    UnsupportedType,
    /// Unsupported proof purpose
    UnsupportedProofPurpose,
    /// Unsupported check
    UnsupportedCheck,
    /// Blank node identifier in predicate is unsupported
    UnsupportedBlankPredicate,
    /// Unsupported JWT VC in VP
    JWTCredentialInPresentation,
    /// Linked data proof option unencodable as JWT claim
    UnencodableOptionClaim(String),
    /// Expected unencoded JWT header
    ExpectedUnencodedHeader,
    /// Resource not found
    ResourceNotFound(String),
    /// Invalid ProofType type
    InvalidProofTypeType,
    /// Invalid key length
    InvalidKeyLength,
    /// Inconsistent DID Key
    InconsistentDIDKey,
    /// Crypto error from `ring` crate
    RingError,
    /// Expected object
    ExpectedObject,
    /// Expected array
    ExpectedArray,
    /// Expected string
    ExpectedString,
    /// Expected string for publicKeyMultibase
    ExpectedStringPublicKeyMultibase,
    /// Unexpected length for publicKeyMultibase
    MultibaseKeyLength(usize, usize),
    /// Unexpected multibase (multicodec) key prefix multicodec
    MultibaseKeyPrefix,
    /// Expected object with @list key
    ExpectedList,
    /// Expected array in @list
    ExpectedArrayList,
    /// Expected object with @value key
    ExpectedValue,
    /// Missing graph
    MissingGraph,
    /// Missing active property
    MissingActiveProperty,
    /// Missing active property entry
    MissingActivePropertyEntry,
    /// [Multiple conflicting for the same node](https://w3c.github.io/json-ld-api/#dom-jsonlderrorcode-conflicting-indexes)
    ConflictingIndexes,
    /// Value object with @type must not contain @language or @direction
    ValueObjectLanguageType,
    /// Unexpected keyword in object
    UnexpectedKeyword,
    /// Unexpected IRI in object
    UnexpectedIRI,
    /// Value object expected @json @type for array or object value
    ExpectedValueTypeJson,
    /// Unrecognized @direction value
    UnrecognizedDirection,
    /// Expected string value for @index key of value object
    ExpectedStringIndex,
    /// Unexpected nested array
    UnexpectedNestedArray,
    /// Unexpected @value key
    UnexpectedValue,
    /// Unexpected @list key
    UnexpectedList,
    /// Unexpected @set key
    UnexpectedSet,
    /// [`representationNotSupported`](https://www.w3.org/TR/did-spec-registries/#representationnotsupported) DID resolution error
    RepresentationNotSupported,
    /// Expected rdf:langString type with language-tagged string literal
    ExpectedLangStringType,
    /// IRI reference not well-formed
    IRIRefNotWellFormed,
    /// Unable to serialize double
    SerializeDouble,
    /// Expected failure
    ExpectedFailure,
    /// Expected multibase Z prefix (base58)
    ExpectedMultibaseZ,
    /// Unable to encode Signed Tezos Message
    EncodeTezosSignedMessage(EncodeTezosSignedMessageError),
    /// Unable to decode Tezos Signature
    DecodeTezosSignature(DecodeTezosSignatureError),
    /// Output did not match expected value.
    ExpectedOutput(String, String),
    /// Unknown JSON-LD processing mode
    UnknownProcessingMode(String),
    /// Unknown RDF direction
    UnknownRdfDirection(String),
    #[cfg(feature = "ring")]
    /// Error parsing a key with `ring`
    KeyRejected(KeyRejectedError),
    /// Error parsing a UTF-8 string
    FromUtf8(FromUtf8Error),
    /// Error from `rsa` crate
    #[cfg(feature = "rsa")]
    Rsa(RsaError),
    /// Error from `ed25519-dalek` crate
    #[cfg(feature = "ed25519-dalek")]
    ED25519(ED25519Error),
    /// Error from `k256` crate
    #[cfg(feature = "k256")]
    Secp256k1(Secp256k1Error),
    /// Error from `p256` crate
    #[cfg(feature = "p256")]
    Secp256r1(Secp256r1Error),
    /// Error encoding ASN.1 data structure.
    ASN1Encode(ASN1EncodeError),
    /// Error decoding Base64
    Base64(Base64Error),
    /// Error parsing or producing multibase
    Multibase(MultibaseError),
    /// Error from `json` crate
    JSON(JSONError),
    /// Error from `serde_json` crate
    SerdeJSON(SerdeJSONError),
    /// Error from `serde_urlencoded` crate
    SerdeUrlEncoded(SerdeUrlEncodedError),
    /// Error from `json-ld` crate
    JSONLD(JSONLDErrorCode),
    /// Error from `iref` crate
    IRI(IRIError),
    /// Error parsing integer
    ParseInt(ParseIntError),
    /// Error parsing a char
    CharTryFrom(CharTryFromError),
    /// Error converting slice to array
    TryFromSlice(TryFromSliceError),
    /// Aleo signing error
    #[cfg(feature = "aleosig")]
    AleoSign(AleoSignError),
    /// Aleo verification error
    #[cfg(feature = "aleosig")]
    AleoVerify(AleoVerifyError),
    /// Unexpected CAIP-2 namespace
    UnexpectedCAIP2Namepace(String, String),
    /// Unexpected Aleo namespace
    UnexpectedAleoNetwork(String, String),
    #[cfg(feature = "aleosig")]
    /// Error generating Aleo private key
    AleoGeneratePrivateKey(AleoGeneratePrivateKeyError),
    /// Error parsing CAIP-10 blockchain account id
    BlockchainAccountIdParse(BlockchainAccountIdParseError),
    /// Error verifying CAIP-10 blockchain account id against a public key
    BlockchainAccountIdVerify(BlockchainAccountIdVerifyError),
    /// Error constructing EIP-712 TypedData from a linked data document using JSON-LD/RDF
    #[cfg(feature = "keccak-hash")]
    TypedDataConstruction(TypedDataConstructionError),
    /// Error constructing EIP-712 TypedData from a linked data document using JSON
    #[cfg(feature = "keccak-hash")]
    TypedDataConstructionJSON(TypedDataConstructionJSONError),
    /// Error hashing EIP-712 data
    #[cfg(feature = "keccak-hash")]
    TypedDataHash(TypedDataHashError),
    /// Error decoding hex data
    FromHex(hex::FromHexError),
    /// Error decoding Base58 data
    Base58(bs58::decode::Error),
    /// Expected string beginning with '0x'
    HexString,
    /// Expected string to contain only lowercase
    ExpectedLowercase,
    /// Unknown signature prefix
    SignaturePrefix,
    /// Unknown key prefix
    KeyPrefix,
    /// Unable to resolve DID
    UnableToResolve(String),
    /// Expected 64 byte uncompressed key or 33 bytes compressed key
    P256KeyLength(usize),
    /// Unable to encode elliptic curve key
    ECEncodingError,
    /// Unable to decompress elliptic curve
    ECDecompress,
    /// Error from `k256` crate
    #[cfg(feature = "k256")]
    K256EC(k256::elliptic_curve::Error),
    /// Error from `p256` crate
    #[cfg(feature = "p256")]
    P256EC(p256::elliptic_curve::Error),
    /// Missing crate features
    MissingFeatures(&'static str),
    NumericDateOutOfMicrosecondPrecisionRange,
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
            Error::MissingExponent => write!(f, "Missing exponent in RSA key"),
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
            Error::MissingVerificationRelationship(issuer, proof_purpose, vm) => write!(f, "Missing verification relationship. Issuer: {}. Proof purpose: {:?}. Verification method id: {}", issuer, proof_purpose, vm),
            Error::MissingCredential => write!(f, "Verifiable credential not found in JWT"),
            Error::MissingPresentation => write!(f, "Verifiable presentation not found in JWT"),
            Error::Key => write!(f, "problem with JWT key"),
            Error::Secp256k1Parse(s) => write!(f, "problem parsing secp256k1 key: {}", s),
            Error::Secp256r1Parse(s) => write!(f, "problem parsing secp256r1 key: {}", s),
            Error::MultipleKeyMaterial => write!(f, "A verification method MUST NOT contain multiple verification material properties for the same material."),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::AlgorithmNotImplemented => write!(f, "JWA algorithm not implemented"),
            Error::ProofTypeNotImplemented => write!(f, "Linked Data Proof type not implemented"),
            Error::MissingAlgorithm => write!(f, "Missing algorithm in JWT"),
            Error::MissingCurve => write!(f, "Missing curve in JWK"),
            Error::MissingPoint => write!(f, "Missing elliptic curve point in JWK"),
            Error::MissingKeyValue => write!(f, "Missing key value for symmetric key"),
            Error::MissingIdentifier => write!(f, "Missing identifier"),
            Error::MissingChosenIssuer => write!(f, "Missing chosen issuer"),
            Error::ExpectedTerm => write!(f, "Expected RDF term"),
            Error::ExpectedNQuad => write!(f, "Expected RDF N-Quad"),
            Error::ExpectedLiteral => write!(f, "Expected RDF Literal"),
            Error::ExpectedBlankNodeLabel => write!(f, "Expected RDF blank node label"),
            Error::ExpectedIRIRef => write!(f, "Expected RDF IRI reference"),
            Error::ExpectedLang => write!(f, "Expected RDF language tag"),
            Error::AlgorithmMismatch => write!(f, "Algorithm in JWS header does not match JWK"),
            Error::KeyIdVMMismatch(vm, kid) => write!(f, "Verification method id does not match JWK id. VM id: {}, JWK key id: {}", vm, kid),
            Error::ObjectMismatch(predicate, expected, actual) => write!(f, "RDF statement object does not match value. Predicate: {}. Expected: {}. Actual: {}", predicate, expected, actual),
            Error::ExpectedObjectForPredicate(predicate, expected) => write!(f, "Missing RDF statement object. Predicate: {}. Expected value: {}", predicate, expected),
            Error::UnexpectedObjectForPredicate(predicate, value) => write!(f, "Unexpected RDF statement object. Predicate: {}. Value: {}", predicate, value),
            Error::MissingType => write!(f, "Missing type"),
            Error::MissingStatement => write!(f, "Missing RDF statement"),
            Error::UnexpectedEndOfList => write!(f, "Unexpected end of list"),
            Error::ListItemMismatch(rdf_value, json_value) => write!(f, "List item mismatch. Value in RDF: {}. Value in JSON: {}", rdf_value, json_value),
            Error::ExpectedEndOfList => write!(f, "Expected end of list"),
            Error::ExpectedRestOfList => write!(f, "Expected rest of list"),
            Error::ExpectedListValue => write!(f, "Expected list value"),
            Error::UnexpectedTriple(triple) => write!(f, "Unexpected triple: {:?}", triple),
            Error::KeyMismatch => write!(f, "Key mismatch"),
            Error::VerificationMethodMismatch => write!(f, "Verification method mismatch"),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
            Error::UnsupportedCurve => write!(f, "Unsupported curve"),
            Error::UnsupportedMultipleVMs => write!(f, "Unsupported multiple verification methods"),
            Error::UnsupportedNonDIDIssuer(issuer) => write!(f, "Unsupported non-DID issuer: {}", issuer),
            Error::KeyTypeNotImplemented => write!(f, "Key type not implemented"),
            Error::CurveNotImplemented(curve) => write!(f, "Curve not implemented: '{:?}'", curve),
            Error::TimeError => write!(f, "Unable to convert date/time"),
            Error::InvalidContext => write!(f, "Invalid context"),
            Error::ControllerLimit => write!(f, "DID controller limit exceeded"),
            Error::MissingContext => write!(f, "Missing context"),
            Error::MissingDocumentId => write!(f, "Missing document ID"),
            Error::MissingProofSignature => write!(f, "Missing JWS in proof"),
            Error::ExpiredProof => write!(f, "Expired proof"),
            Error::FutureProof => write!(f, "Proof creation time is in the future"),
            Error::InvalidSignature => write!(f, "Invalid Signature"),
            Error::UnexpectedSignatureLength(expected, actual) => write!(f, "Expected signature length {} but found {}", expected, actual),
            Error::InvalidJWS => write!(f, "Invalid JWS"),
            Error::MissingJWSHeader => write!(f, "Missing JWS Header"),
            Error::InvalidProofPurpose => write!(f, "Invalid proof purpose"),
            Error::MissingProofPurpose => write!(f, "Missing proof purpose"),
            Error::InvalidProofDomain => write!(f, "Invalid proof domain"),
            Error::MissingCredentialSchema => write!(f, "Missing credential schema for ZKP"),
            Error::UnsupportedProperty => write!(f, "Unsupported property for LDP"),
            Error::UnsupportedKeyType => write!(f, "Unsupported key type"),
            Error::UnsupportedType => write!(f, "Unsupported type for LDP"),
            Error::UnsupportedProofPurpose => write!(f, "Unsupported proof purpose"),
            Error::UnsupportedCheck => write!(f, "Unsupported check"),
            Error::UnsupportedBlankPredicate => write!(f, "Blank node identifier in predicate is unsupported"),
            Error::JWTCredentialInPresentation => write!(f, "Unsupported JWT VC in VP"),
            Error::UnencodableOptionClaim(name) => write!(f, "Linked data proof option unencodable as JWT claim: {}", name),
            Error::ExpectedUnencodedHeader => write!(f, "Expected unencoded JWT header"),
            Error::ResourceNotFound(id) => write!(f, "Resource not found: {}", id),
            Error::InvalidProofTypeType => write!(f, "Invalid ProofType type"),
            Error::InvalidKeyLength => write!(f, "Invalid key length"),
            Error::InconsistentDIDKey => write!(f, "Inconsistent DID Key"),
            Error::DIDURL => write!(f, "Invalid DID URL"),
            Error::UnexpectedDIDFragment => write!(f, "Unexpected DID fragment"),
            Error::DIDURLDereference(error) => write!(f, "Unable to dereference DID URL: {}", error),
            Error::URI => write!(f, "Invalid URI"),
            Error::RingError => write!(f, "Crypto error"),
            Error::ExpectedObject => write!(f, "Expected object"),
            Error::ExpectedArray => write!(f, "Expected array"),
            Error::ExpectedString => write!(f, "Expected string"),
            Error::ExpectedStringPublicKeyMultibase => write!(f, "Expected string for publicKeyMultibase"),
            Error::MultibaseKeyLength(expected, found) => write!(f, "Expected length {} for publicKeyMultibase but found {}", expected, found),
            Error::MultibaseKeyPrefix => write!(f, "Invalid Multibase key prefix"),
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
            Error::ExpectedMultibaseZ => write!(f, "Expected multibase Z prefix (base58)"),
            Error::EncodeTezosSignedMessage(e) => write!(f, "Unable to encode Signed Tezos Message: {}", e),
            Error::DecodeTezosSignature(e) => write!(f, "Unable to decode Tezos Signature: {}", e),
            Error::ExpectedOutput(expected, found) => write!(f, "Expected output '{}', but found '{}'", expected, found),
            Error::UnexpectedCAIP2Namepace(expected, found) => write!(f, "Expected CAIP-2 namespace '{}' but found '{}'", expected, found),
            Error::UnexpectedAleoNetwork(expected, found) => write!(f, "Expected Aleo network '{}' but found '{}'", expected, found),
            Error::UnknownProcessingMode(mode) => write!(f, "Unknown processing mode '{}'", mode),
            Error::UnknownRdfDirection(direction) => write!(f, "Unknown RDF direction '{}'", direction),
            Error::HexString => write!(f, "Expected string beginning with '0x'"),
            Error::ExpectedLowercase => write!(f, "Expected string to contain only lowercase"),
            Error::SignaturePrefix => write!(f, "Unknown signature prefix"),
            Error::KeyPrefix => write!(f, "Unknown key prefix"),
            Error::UnableToResolve(error) => write!(f, "Unable to resolve: {}", error),
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
            #[cfg(feature = "aleosig")]
            Error::AleoSign(e) => e.fmt(f),
            #[cfg(feature = "aleosig")]
            Error::AleoVerify(e) => e.fmt(f),
            #[cfg(feature = "aleosig")]
            Error::AleoGeneratePrivateKey(e) => e.fmt(f),
            #[cfg(feature = "keccak-hash")]
            Error::TypedDataConstruction(e) => e.fmt(f),
            #[cfg(feature = "keccak-hash")]
            Error::TypedDataConstructionJSON(e) => e.fmt(f),
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
            Error::MissingFeatures(features) => write!(f, "Missing features: {}", features),
            Error::NumericDateOutOfMicrosecondPrecisionRange => write!(f, "Out of valid microsecond-precision range of NumericDate"),
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

#[cfg(feature = "aleosig")]
impl From<AleoSignError> for Error {
    fn from(err: AleoSignError) -> Error {
        Error::AleoSign(err)
    }
}

#[cfg(feature = "aleosig")]
impl From<AleoVerifyError> for Error {
    fn from(err: AleoVerifyError) -> Error {
        Error::AleoVerify(err)
    }
}

#[cfg(feature = "keccak-hash")]
impl From<TypedDataConstructionError> for Error {
    fn from(err: TypedDataConstructionError) -> Error {
        Error::TypedDataConstruction(err)
    }
}

#[cfg(feature = "keccak-hash")]
impl From<TypedDataConstructionJSONError> for Error {
    fn from(err: TypedDataConstructionJSONError) -> Error {
        Error::TypedDataConstructionJSON(err)
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

impl From<EncodeTezosSignedMessageError> for Error {
    fn from(err: EncodeTezosSignedMessageError) -> Error {
        Error::EncodeTezosSignedMessage(err)
    }
}

impl From<DecodeTezosSignatureError> for Error {
    fn from(err: DecodeTezosSignatureError) -> Error {
        Error::DecodeTezosSignature(err)
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
