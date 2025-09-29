use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);

type Base64urlUIntString = String;

const BASE64_URL_SAFE_INDIFFERENT_PAD: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

impl TryFrom<String> for Base64urlUInt {
    type Error = base64::DecodeError;
    fn try_from(data: String) -> Result<Self, Self::Error> {
        Ok(Base64urlUInt(BASE64_URL_SAFE_INDIFFERENT_PAD.decode(data)?))
    }
}

impl From<&Base64urlUInt> for String {
    fn from(data: &Base64urlUInt) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&data.0)
    }
}

impl From<Base64urlUInt> for Base64urlUIntString {
    fn from(data: Base64urlUInt) -> Base64urlUIntString {
        String::from(&data)
    }
}
