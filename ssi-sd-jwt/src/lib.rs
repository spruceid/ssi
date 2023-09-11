mod decode;
pub(crate) mod digest;
pub(crate) mod encode;
pub(crate) mod verify;

pub use decode::{decode_verify, ValidityClaims};
pub use digest::{hash_encoded_disclosure, SdAlg};
pub use encode::{encode_disclosure, encode_disclosure_with_rng, encode_sign, UnencodedDisclosure};
pub use verify::verify_sd_disclosures_array;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("JWT is missing _sd_alg property")]
    MissingSdAlg,
    #[error("Unknown value of _sd_alg {0}")]
    UnknownSdAlg(String),
    #[error("Multiple disclosures given with the same hash")]
    MultipleDisclosuresWithSameHash,
    #[error("An _sd claim wasn't a string")]
    SdClaimNotString,
    #[error("A disclosure claim would collid with an existing JWT claim")]
    DisclosureClaimCollidesWithJwtClaim,
    #[error("A disclosure didn't have the correct array length")]
    DisclosureArrayLength,
    #[error("A disclosure didn't contain the right types for elements")]
    DisclosureHasWrongType,
    #[error("A single disclosure was used multiple times")]
    DisclosureUsedMultipleTimes,
    #[error("Found an array item disclosure when expecting a property type")]
    ArrayDisclosureWhenExpectingProperty,
    #[error("Found a property type disclosure when expecting an array item")]
    PropertyDisclosureWhenExpectingArray,
    #[error("The base claims to encode did not become a JSON object")]
    EncodedAsNonObject,
    #[error("The base claims to encode contained a property reserved by SD-JWT")]
    EncodedClaimsContainsReservedProperty,
    #[error("A property for an array sd claim was not an array")]
    ExpectedArray,
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    JsonSerialization(#[from] serde_json::Error),
}

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_CLAIM_ITEM_PROPERTY_NAME: &str = "...";
