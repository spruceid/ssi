//! Selective Disclosure for JWTs ([SD-JWT]).
//!
//! [SD-JWT]: <https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/>
#![warn(missing_docs)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_jws::{CompactJWSStr, DecodedJWSRef};
use ssi_jwt::JWTClaims;
use std::{
    collections::BTreeMap,
    fmt::{self, Write},
};

pub(crate) mod digest;
mod disclose;
pub(crate) mod disclosure;
pub(crate) mod encode;
mod error;
pub(crate) mod utils;
mod verify;

pub use digest::{hash_encoded_disclosure, SdAlg};
use disclosure::{DecodedDisclosure, Disclosure};
pub use encode::{
    encode_array_disclosure, encode_property_disclosure, encode_sign, UnencodedDisclosure,
};
pub use error::{DecodeError, EncodeError};
use utils::is_url_safe_base64_char;

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_CLAIM_ITEM_PROPERTY_NAME: &str = "...";

/// Invalid SD-JWT error.
#[derive(Debug, thiserror::Error)]
#[error("invalid SD-JWT: `{0}`")]
pub struct InvalidSdJwt<T>(pub T);

/// SD-JWT in compact form.
///
/// # Grammar
///
/// ```abnf
/// ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
/// DIGIT = %x30-39 ; 0-9
/// BASE64URL = 1*(ALPHA / DIGIT / "-" / "_")
/// JWT = BASE64URL "." BASE64URL "." BASE64URL
/// DISCLOSURE = BASE64URL
/// SD-JWT = JWT "~" *[DISCLOSURE "~"]
/// ```
pub struct SdJwt([u8]);

impl SdJwt {
    /// Parses the given `input` as an SD-JWT.
    ///
    /// Returns an error if it is not a valid SD-JWT.
    pub fn new<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<&Self, InvalidSdJwt<&T>> {
        let bytes = input.as_ref();
        if Self::validate(bytes) {
            Ok(unsafe { Self::new_unchecked(bytes) })
        } else {
            Err(InvalidSdJwt(input))
        }
    }

    /// Checks that the given input is a SD-JWT.
    pub fn validate(input: &[u8]) -> bool {
        let Some(jwt_end) = input.iter().copied().position(|c| c == b'~') else {
            return false;
        };

        let mut end_with_separator = true;
        for &b in &input[(jwt_end + 1)..] {
            if is_url_safe_base64_char(b) {
                end_with_separator = false
            } else if b == b'~' {
                if end_with_separator {
                    return false;
                }

                end_with_separator = true
            } else {
                return false;
            }
        }

        end_with_separator
    }

    /// Creates a new SD-JWT from the given `input` without validation.
    ///
    /// # Safety
    ///
    /// The input value **must** be a valid SD-JWT.
    pub unsafe fn new_unchecked(input: &[u8]) -> &Self {
        std::mem::transmute(input)
    }

    /// Returns the byte-position just after the issuer-signed JWT.
    fn jwt_end(&self) -> usize {
        self.0.iter().copied().position(|c| c == b'~').unwrap()
    }

    /// Returns the issuer-signed JWT.
    pub fn jwt(&self) -> &CompactJWSStr {
        unsafe {
            // SAFETY: we already validated the SD-JWT and know it
            // starts with a valid JWT.
            CompactJWSStr::new_unchecked(&self.0[..self.jwt_end()])
        }
    }

    /// Returns an iterator over the disclosures of the SD-JWT.
    pub fn disclosures(&self) -> Disclosures {
        Disclosures {
            bytes: &self.0,
            offset: self.jwt_end() + 1,
        }
    }

    /// Returns references to each part of this SD-JWT.
    pub fn parts(&self) -> PartsRef {
        PartsRef {
            jwt: self.jwt(),
            disclosures: self.disclosures().collect(),
        }
    }

    /// Decode a compact SD-JWT.
    pub fn decode(&self) -> Result<DecodedSdJwtRef, DecodeError> {
        self.parts().decode()
    }
}

/// Iterator over the disclosures of an SD-JWT.
pub struct Disclosures<'a> {
    /// SD-JWT bytes.
    bytes: &'a [u8],

    /// Offset of the beginning of the next disclosure (if any).
    offset: usize,
}

impl<'a> Iterator for Disclosures<'a> {
    type Item = &'a Disclosure;

    fn next(&mut self) -> Option<Self::Item> {
        let mut i = self.offset;

        while i < self.offset {
            if self.bytes[i] == b'~' {
                let disclosure = unsafe {
                    // SAFETY: we already validated the SD-JWT and know
                    // it is composed of valid disclosures.
                    Disclosure::new_unchecked(&self.bytes[self.offset..i])
                };

                self.offset = i + 1;
                return Some(disclosure);
            }

            i += 1
        }

        None
    }
}

/// SD-JWT components to be presented for decoding and validation whether coming
/// from a compact representation, enveloping JWT, etc.
#[derive(Debug, PartialEq)]
pub struct PartsRef<'a> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: &'a CompactJWSStr,

    /// Disclosures for associated JWT
    pub disclosures: Vec<&'a Disclosure>,
}

impl<'a> PartsRef<'a> {
    /// Creates a new `PartsRef`.
    pub fn new(jwt: &'a CompactJWSStr, disclosures: Vec<&'a Disclosure>) -> Self {
        Self { jwt, disclosures }
    }

    /// Decode the JWT-SD parts.
    pub fn decode(self) -> Result<DecodedSdJwtRef<'a>, DecodeError> {
        Ok(DecodedSdJwtRef {
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

    // /// Convert Deserialized into a compact serialized format
    // pub fn compact_serialize(&self) -> String {
    //     serialize_string_format(self.jwt, &self.disclosures)
    // }
}

impl<'a> fmt::Display for PartsRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jwt.fmt(f)?;
        f.write_char('~')?;

        for d in &self.disclosures {
            d.fmt(f)?;
            f.write_char('~')?;
        }

        Ok(())
    }
}

/// Undisclosed SD-JWT payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtPayload {
    /// Hash algorithm used by the Issuer to generate the digests.
    #[serde(rename = "_sd_alg")]
    pub sd_alg: SdAlg,

    /// Other claims.
    #[serde(flatten)]
    pub claims: BTreeMap<String, Value>,
}

/// Decoded SD-JWT.
pub struct DecodedSdJwtRef<'a> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: DecodedJWSRef<'a, SdJwtPayload>,

    /// Disclosures for associated JWT.
    pub disclosures: Vec<DecodedDisclosure<'a>>,
}

// /// Decoded SD-JWT.
// pub struct DecodedSdJwt {
//     /// JWT who's claims can be selectively disclosed.
//     pub jwt: DecodedJWT<SdJwtPayload>,

//     /// Disclosures for associated JWT.
//     pub disclosures: Vec<String>
// }

/// Disclosed SD-JWT, ready to be verified.
pub struct DisclosedSdJwt<'a, T> {
    /// Undisclosed decoded JWT.
    pub undisclosed_jwt: DecodedJWSRef<'a, SdJwtPayload>,

    /// Disclosed JWT claims.
    pub claims: JWTClaims<T>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED: &str = concat!(
        "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1Fya",
        "zFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZ",
        "zZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZ",
        "kx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1R",
        "Ew4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSL",
        "WFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzI",
        "iwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAic",
        "zBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzI",
        "jogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsI",
        "CJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTS",
        "jFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1c",
        "FJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZ",
        "Xd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2b",
        "mNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4a",
        "nZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25Vb",
        "GRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0M",
        "G9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R",
        "3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.rFsowW-KSZe7EITlWsGajR9nnG",
        "BLlQ78qgtdGIZg3FZuZnxtapP0H8CUMnffJAwPQJmGnpFpulTkLWHiI1kMmw~WyJHMDJ",
        "OU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJs",
        "a2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ~"
    );

    const JWT: &str = concat!(
        "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1Fya",
        "zFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZ",
        "zZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZ",
        "kx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1R",
        "Ew4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSL",
        "WFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzI",
        "iwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAic",
        "zBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzI",
        "jogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsI",
        "CJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTS",
        "jFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1c",
        "FJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZ",
        "Xd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2b",
        "mNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4a",
        "nZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25Vb",
        "GRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0M",
        "G9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R",
        "3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.rFsowW-KSZe7EITlWsGajR9nnG",
        "BLlQ78qgtdGIZg3FZuZnxtapP0H8CUMnffJAwPQJmGnpFpulTkLWHiI1kMmw"
    );

    const DISCLOSURE_0: &str =
        "WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ";
    const DISCLOSURE_1: &str = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ";

    #[test]
    fn deserialize() {
        assert_eq!(
            SdJwt::new(ENCODED).unwrap().parts(),
            PartsRef::new(
                CompactJWSStr::new(JWT).unwrap(),
                vec![
                    Disclosure::new(DISCLOSURE_0).unwrap(),
                    Disclosure::new(DISCLOSURE_1).unwrap()
                ]
            )
        )
    }

    #[test]
    fn deserialize_fails_with_emtpy() {
        assert!(SdJwt::new("").is_err())
    }

    #[test]
    fn serialize_parts() {
        assert_eq!(
            PartsRef::new(
                CompactJWSStr::new(JWT).unwrap(),
                vec![
                    Disclosure::new(DISCLOSURE_0).unwrap(),
                    Disclosure::new(DISCLOSURE_1).unwrap()
                ]
            )
            .to_string(),
            ENCODED,
        )
    }
}
