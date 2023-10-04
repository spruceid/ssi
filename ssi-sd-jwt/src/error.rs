#[derive(thiserror::Error, Debug)]
pub enum DecodeError {
    #[error("Unable to deserialize string format of concatenated tildes")]
    UnableToDeserializeStringFormat,
    #[error("JWT is missing _sd_alg property")]
    MissingSdAlg,
    #[error("Unknown value of _sd_alg {0}")]
    UnknownSdAlg(String),
    #[error("Multiple disclosures given with the same hash")]
    MultipleDisclosuresWithSameHash,
    #[error("An _sd claim wasn't a string")]
    SdClaimNotString,
    #[error("And _sd property was not an array type")]
    SdPropertyNotArray,
    #[error("A disclosure claim would collid with an existing JWT claim")]
    DisclosureClaimCollidesWithJwtClaim,
    #[error("A disclosure is malformed")]
    DisclosureMalformed,
    #[error("A single disclosure was used multiple times")]
    DisclosureUsedMultipleTimes,
    #[error("Found an array item disclosure when expecting a property type")]
    ArrayDisclosureWhenExpectingProperty,
    #[error("Found a property type disclosure when expecting an array item")]
    PropertyDisclosureWhenExpectingArray,
    #[error("A disclosure was not used during decoding")]
    UnusedDisclosure,
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    JsonDeserialization(#[from] serde_json::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum EncodeError {
    #[error("The base claims to encode did not become a JSON object")]
    EncodedAsNonObject,
    #[error("The base claims to encode contained a property reserved by SD-JWT")]
    EncodedClaimsContainsReservedProperty,
    #[error("A property for an array sd claim was not an array")]
    ExpectedArray,
    #[error("A disclosure was not used during decoding")]
    UnusedDisclosure,
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    JsonSerialization(#[from] serde_json::Error),
}
