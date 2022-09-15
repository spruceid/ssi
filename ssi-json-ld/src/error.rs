//! Error types for `ssi-json-ld` crate
use iref::Error as IRIError;
use json::Error as JSONError;
use json_ld::Error as JSONLDError;
use json_ld::ErrorCode as JSONLDErrorCode;
use serde_json::Error as SerdeJSONError;
use thiserror::Error;

/// Error type for `ssi-json-ld`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Missing identifier
    #[error("Missing identifier")]
    MissingIdentifier,
    /// Missing chosen issuer
    #[error("Missing chosen issuer")]
    MissingChosenIssuer,
    /// Expected RDF term
    #[error("Expected RDF term")]
    ExpectedTerm,
    /// Expected RDF N-Quad
    #[error("Expected RDF N-Quad")]
    ExpectedNQuad,
    /// Expected RDF Literal
    #[error("Expected RDF Literal")]
    ExpectedLiteral,
    /// Expected RDF blank node label
    #[error("Expected RDF blank node label")]
    ExpectedBlankNodeLabel,
    /// Expected RDF IRI reference
    #[error("Expected RDF IRI reference")]
    ExpectedIRIRef,
    /// Expected RDF language tag
    #[error("Expected RDF language tag")]
    ExpectedLang,
    /// RDF statement object does not match value
    #[error(
        "RDF statement object does not match value. Predicate: {0}. Expected: {1}. Actual: {2}"
    )]
    ObjectMismatch(String, String, String),
    /// Missing RDF statement object
    #[error("Missing RDF statement object. Predicate: {0}. Expected value: {1}")]
    ExpectedObjectForPredicate(String, String),
    /// Unexpected RDF statement object
    #[error("Unexpected RDF statement object. Predicate: {0}. Value: {1}")]
    UnexpectedObjectForPredicate(String, String),
    /// Missing RDF statement
    #[error("Missing RDF statement")]
    MissingStatement,
    /// Unexpected end of list
    #[error("Unexpected end of list")]
    UnexpectedEndOfList,
    /// List item mismatch
    #[error("List item mismatch. Value in RDF: {0}. Value in JSON: {1}")]
    ListItemMismatch(String, String),
    /// Expected end of list
    #[error("Expected end of list")]
    ExpectedEndOfList,
    /// Expected rest of list
    #[error("Expected rest of list")]
    ExpectedRestOfList,
    /// Expected list value
    #[error("Expected list value")]
    ExpectedListValue,
    /// Unexpected triple
    #[error("Unexpected triple {0:?}")]
    UnexpectedTriple(crate::rdf::Triple),
    /// Blank node identifier in predicate is unsupported
    #[error("Blank node identifier in predicate is unsupported")]
    UnsupportedBlankPredicate,
    /// Expected object
    #[error("Expected object")]
    ExpectedObject,
    /// Expected array
    #[error("Expected array")]
    ExpectedArray,
    /// Expected string
    #[error("Expected string")]
    ExpectedString,
    /// Expected object with @list key
    #[error("Expected object with @list key")]
    ExpectedList,
    /// Expected array in @list
    #[error("Expected array in @list")]
    ExpectedArrayList,
    /// Expected object with @value key
    #[error("Expected object with @value key")]
    ExpectedValue,
    /// Missing graph
    #[error("Missing graph")]
    MissingGraph,
    /// Missing active property
    #[error("Missing active property")]
    MissingActiveProperty,
    /// Missing active property entry
    #[error("Missing active property entry")]
    MissingActivePropertyEntry,
    /// [Multiple conflicting for the same node](https://w3c.github.io/json-ld-api/#dom-jsonlderrorcode-conflicting-indexes)
    #[error("Multiple conflicting for the same node")]
    ConflictingIndexes,
    /// Value object with @type must not contain @language or @direction
    #[error("Value object with @type must not contain @language or @direction")]
    ValueObjectLanguageType,
    /// Unexpected keyword in object
    #[error("Unexpected keyword in object")]
    UnexpectedKeyword,
    /// Unexpected IRI in object
    #[error("Unexpected IRI in object")]
    UnexpectedIRI,
    /// Value object expected @json @type for array or object value
    #[error("Value object expected @json @type for array or object value")]
    ExpectedValueTypeJson,
    /// Unrecognized @direction value
    #[error("Unrecognized @direction value")]
    UnrecognizedDirection,
    /// Expected string value for @index key of value object
    #[error("Expected string value for @index key of value object")]
    ExpectedStringIndex,
    /// Unexpected nested array
    #[error("Unexpected nested array")]
    UnexpectedNestedArray,
    /// Unexpected @value key
    #[error("Unexpected @value key")]
    UnexpectedValue,
    /// Unexpected @list key
    #[error("Unexpected @list key")]
    UnexpectedList,
    /// Unexpected @set key
    #[error("Unexpected @set key")]
    UnexpectedSet,
    /// Expected rdf:langString type with language-tagged string literal
    #[error("Expected rdf:langString type with language-tagged string literal")]
    ExpectedLangStringType,
    /// IRI reference not well-formed
    #[error("IRI reference not well-formed")]
    IRIRefNotWellFormed,
    /// Unable to serialize double
    #[error("Unable to serialize double")]
    SerializeDouble,
    /// Expected failure
    #[error("Expected failure")]
    ExpectedFailure,
    /// Output did not match expected value.
    #[error("Expected output '{0}', but found '{1}'")]
    ExpectedOutput(String, String),
    /// Unknown JSON-LD processing mode
    #[error("Unknown processing mode {0}")]
    UnknownProcessingMode(String),
    /// Unknown RDF direction
    #[error("Unknown RDF direction '{0}")]
    UnknownRdfDirection(String),
    /// Error from `json` crate
    #[error(transparent)]
    JSON(#[from] JSONError),
    /// Error from `serde_json` crate
    #[error(transparent)]
    SerdeJSON(#[from] SerdeJSONError),
    /// Error from `json-ld` crate
    #[error("{0}")]
    JSONLD(JSONLDErrorCode),
    /// Error from `iref` crate
    #[error(transparent)]
    IRI(#[from] IRIError),
}

impl From<JSONLDError> for Error {
    fn from(err: JSONLDError) -> Error {
        Error::JSONLD(err.code())
    }
}
