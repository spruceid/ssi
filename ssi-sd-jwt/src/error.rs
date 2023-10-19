/// Errors in the decode pathway
#[derive(thiserror::Error, Debug)]
pub enum DecodeError {
    /// Unable to deserialize string format of concatenated tildes
    #[error("Unable to deserialize string format of concatenated tildes")]
    UnableToDeserializeStringFormat,

    /// JWT payload claims were not a JSON object
    #[error("JWT payload claims were not a JSON object")]
    ClaimsWrongType,

    /// JWT is missing _sd_alg property
    #[error("JWT is missing _sd_alg property")]
    MissingSdAlg,

    /// Unknown value of _sd_alg
    #[error("Unknown value of _sd_alg {0}")]
    UnknownSdAlg(String),

    /// Type of _sd_alg was not string
    #[error("Type of _sd_alg was not string")]
    SdAlgWrongType,

    /// Multiple disclosures given with the same hash
    #[error("Multiple disclosures given with the same hash")]
    MultipleDisclosuresWithSameHash,

    /// An _sd claim wasn't a string
    #[error("An _sd claim wasn't a string")]
    SdClaimNotString,

    /// An _sd property was not an array type
    #[error("An _sd property was not an array type")]
    SdPropertyNotArray,

    /// A disclosure claim would collid with an existing JWT claim
    #[error("A disclosure claim would collid with an existing JWT claim")]
    DisclosureClaimCollidesWithJwtClaim,

    /// A disclosure is malformed
    #[error("A disclosure is malformed")]
    DisclosureMalformed,

    /// A single disclosure was used multiple times
    #[error("A single disclosure was used multiple times")]
    DisclosureUsedMultipleTimes,

    /// Found an array item disclosure when expecting a property type
    #[error("Found an array item disclosure when expecting a property type")]
    ArrayDisclosureWhenExpectingProperty,

    /// Found a property type disclosure when expecting an array item
    #[error("Found a property type disclosure when expecting an array item")]
    PropertyDisclosureWhenExpectingArray,

    /// A disclosure was not used during decoding
    #[error("A disclosure was not used during decoding")]
    UnusedDisclosure,

    /// Bubbled up error from ssi_jws
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),

    /// Bubbled up error from serde_json
    #[error(transparent)]
    JsonDeserialization(#[from] serde_json::Error),
}

/// Errors in the Encode pathway
#[derive(thiserror::Error, Debug)]
pub enum EncodeError {
    /// The base claims to encode did not become a JSON object
    #[error("The base claims to encode did not become a JSON object")]
    EncodedAsNonObject,

    /// The base claims to encode contained a property reserved by SD-JWT
    #[error("The base claims to encode contained a property reserved by SD-JWT")]
    EncodedClaimsContainsReservedProperty,

    /// A property for an array sd claim was not an array
    #[error("A property for an array sd claim was not an array")]
    ExpectedArray,

    /// A disclosure was not used during decoding
    #[error("A disclosure was not used during decoding")]
    UnusedDisclosure,

    /// Bubbled up error from ssi_jws
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),

    /// Bubbled up error from serde_json
    #[error(transparent)]
    JsonSerialization(#[from] serde_json::Error),
}
