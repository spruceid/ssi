mod decode;
pub(crate) mod digest;
pub(crate) mod encode;
mod error;
pub(crate) mod serialized;
pub(crate) mod verify;

pub use decode::{decode_verify, decode_verify_disclosure_array, ValidityClaims};
pub use digest::{hash_encoded_disclosure, SdAlg};
pub use encode::{
    encode_array_disclosure, encode_property_disclosure, encode_sign, UnencodedDisclosure,
};
pub use error::{DecodeError, EncodeError};
pub use serialized::{deserialize_string_format, serialize_string_format};
pub use verify::verify_sd_disclosures_array;

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_CLAIM_ITEM_PROPERTY_NAME: &str = "...";

#[derive(Debug)]
pub struct Disclosure {
    pub encoded: String,
    pub hash: String,
}
