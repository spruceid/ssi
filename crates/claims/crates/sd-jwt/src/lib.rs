//! Selective Disclosure for JWTs ([SD-JWT]).
//! 
//! [SD-JWT]: <https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/>
#![warn(missing_docs)]
mod decode;
pub(crate) mod digest;
pub(crate) mod disclosure;
pub(crate) mod encode;
mod error;
pub(crate) mod serialized;

pub use decode::{decode_verify, decode_verify_disclosure_array};
pub use digest::{hash_encoded_disclosure, SdAlg};
use disclosure::{DecodedDisclosure, Disclosure};
pub use encode::{
    encode_array_disclosure, encode_property_disclosure, encode_sign,
    UnencodedDisclosure,
};
pub use error::{DecodeError, EncodeError};
use serde::de::DeserializeOwned;
pub use serialized::{deserialize_string_format, serialize_string_format};
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_jwt::{AnyClaims, DecodedJWT, DecodedJWTRef, ToDecodedJWT};

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_CLAIM_ITEM_PROPERTY_NAME: &str = "...";

/// SD-JWT in compact form.
pub struct SdJwt(str);

impl SdJwt {
    /// Returns references to each part of this SD-JWT.
    pub fn parts(&self) -> PartsRef {
        let mut chars = self.0.char_indices();
        
        // Find issuer-signed JWT.
        let jwt = loop {
            if let Some((i, '~')) = chars.next() {
                break unsafe {
                    // SAFETY: we already validated the SD-JWT and know it
                    // starts with a valid JWT.
                    CompactJWSStr::new_unchecked(self.0[..i].as_bytes())
                }
            }
        };

        let mut disclosures = Vec::new();
        let mut i = jwt.len() + 1;
        let key_binding_jwt = loop {
            match chars.next() {
                Some((j, '~')) => {
                    disclosures.push(unsafe {
                        // SAFETY: we already validated the SD-JWT and know
                        // it is composed of valid disclosures.
                        Disclosure::new_unchecked(self.0[i..j].as_bytes())
                    });
                    i = j + 1;
                }
                Some(_) => (),
                None => {
                    break if i < self.0.len() {
                        Some(unsafe {
                            // SAFETY: we already validated the SD-JWT and know
                            // it ends with a valid JWT.
                            CompactJWSStr::new_unchecked(self.0[i..].as_bytes())
                        })
                    } else {
                        None
                    }
                }
            }
        };

        PartsRef {
            jwt,
            disclosures,
            key_binding_jwt
        }
    }

    /// Decode a compact SD-JWT.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<DecodedSdJwtRef<T>, DecodeError> {
        self.parts().decode()
    }
}

/// SD-JWT components to be presented for decodindg and validation whtehre coming from
/// a compact representation, eveloping JWT, etc.
#[derive(Debug, PartialEq)]
pub struct PartsRef<'a> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: &'a CompactJWSStr,

    /// Disclosures for associated JWT
    pub disclosures: Vec<&'a Disclosure>,

    /// Key binding JWT.
    pub key_binding_jwt: Option<&'a CompactJWSStr>
}

impl<'a> PartsRef<'a> {
    /// Decode the JWT-SD parts.
    pub fn decode<T: DeserializeOwned>(self) -> Result<DecodedSdJwtRef<'a, T>, DecodeError> {
        Ok(DecodedSdJwtRef {
            jwt: self.jwt.to_decoded_custom_jwt()?,
            disclosures: self.disclosures.into_iter().map(Disclosure::decode).collect::<Result<_, _>>()?,
            key_binding_jwt: self.key_binding_jwt
        })
    }

    // /// Convert Deserialized into a compact serialized format
    // pub fn compact_serialize(&self) -> String {
    //     serialize_string_format(self.jwt, &self.disclosures)
    // }
}

/// Decoded SD-JWT.
pub struct DecodedSdJwtRef<'a, T = AnyClaims> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: DecodedJWTRef<'a, T>,

    /// Disclosures for associated JWT.
    pub disclosures: Vec<DecodedDisclosure>,

    /// Key binding JWT.
    pub key_binding_jwt: Option<&'a CompactJWSStr>
}

/// Decoded SD-JWT.
pub struct DecodedSdJwt<T = AnyClaims> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: DecodedJWT<T>,

    /// Disclosures for associated JWT.
    pub disclosures: Vec<String>,

    /// Key binding JWT.
    pub key_binding_jwt: Option<CompactJWSString>
}