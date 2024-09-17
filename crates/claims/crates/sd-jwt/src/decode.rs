use crate::{DecodedDisclosure, DecodedSdJwt, Disclosure, PartsRef};

/// Errors in the decode pathway
#[derive(thiserror::Error, Debug)]
pub enum DecodeError {
    /// Unable to decode undisclosed JWT.
    #[error("Unable to decode undisclosed JWT: {0}")]
    UndisclosedJWT(#[from] ssi_jws::DecodeError),

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

impl<'a> PartsRef<'a> {
    /// Decode the JWT-SD parts.
    pub fn decode(self) -> Result<DecodedSdJwt<'a>, DecodeError> {
        Ok(DecodedSdJwt {
            jwt: self
                .jwt
                .decode()?
                .try_map(|bytes| serde_json::from_slice(&bytes))?,
            disclosures: self
                .disclosures
                .into_iter()
                .map(Disclosure::decode)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl Disclosure {
    /// Decode this disclosure.
    pub fn decode(&self) -> Result<DecodedDisclosure, DecodeError> {
        DecodedDisclosure::new(self)
    }
}
