#![warn(missing_docs)]

//! SSI library for processing SD-JWTs

mod decode;
pub(crate) mod digest;
pub(crate) mod disclosure;
pub(crate) mod encode;
mod error;
pub(crate) mod serialized;

pub use decode::{decode_verify, decode_verify_disclosure_array};
pub use digest::{hash_encoded_disclosure, SdAlg};
pub use encode::{
    encode_array_disclosure, encode_property_disclosure, encode_sign, Disclosure,
    UnencodedDisclosure,
};
pub use error::{DecodeError, EncodeError};
pub use serialized::{deserialize_string_format, serialize_string_format};

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_CLAIM_ITEM_PROPERTY_NAME: &str = "...";

/// SD-JWT components to be presented for decodindg and validation whtehre coming from
/// a compact representation, eveloping JWT, etc.
#[derive(Debug, PartialEq)]
pub struct Deserialized<'a> {
    /// JWT who's claims can be selectively disclosed
    pub jwt: &'a str,
    /// Disclosures for associated JWT
    pub disclosures: Vec<&'a str>,
}

impl<'a> Deserialized<'a> {
    /// Convert Deserialized into a compact serialized format
    pub fn compact_serialize(&self) -> String {
        serialize_string_format(self.jwt, &self.disclosures)
    }
}
