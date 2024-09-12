//! Selective Disclosure for JWTs ([SD-JWT]).
//!
//! [SD-JWT]: <https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/>
#![warn(missing_docs)]
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use ssi_claims_core::{
    DateTimeProvider, ProofValidationError, ResolverProvider, SignatureError, ValidateClaims,
    Verification,
};
use ssi_core::{BytesBuf, JsonPointer};
use ssi_jwk::JWKResolver;
use ssi_jws::{CompactJWSStr, DecodedJWS, JWSPayload, JWSSignature, JWSSigner, ValidateJWSHeader};
use ssi_jwt::{AnyClaims, ClaimSet, DecodedJWT, JWTClaims};
use std::{
    borrow::{Borrow, Cow},
    fmt::{self, Write},
    ops::Deref,
};

pub(crate) mod utils;
use utils::is_url_safe_base64_char;

// mod error;
// pub use error::*;

mod digest;
pub use digest::*;

// pub(crate) mod encode;
// pub use encode::{
//     encode_array_disclosure, encode_property_disclosure, encode_sign, UnencodedDisclosure,
// };

mod decode;
pub use decode::*;

mod disclosure;
pub use disclosure::*;

mod conceal;
pub use conceal::*;
// mod sign;
mod disclose;

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

    /// Returns the underlying bytes of the SD-JWT.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns this SD-JWT as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: SD-JWT are valid UTF-8 strings by definition.
            std::str::from_utf8_unchecked(&self.0)
        }
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
    pub fn decode(&self) -> Result<DecodedSdJwt, DecodeError> {
        self.parts().decode()
    }

    /// Decode a compact SD-JWT.
    pub async fn decode_verify_concealed<P>(
        &self,
        params: P,
    ) -> Result<(DecodedSdJwt, Verification), ProofValidationError>
    where
        P: ResolverProvider<Resolver: JWKResolver>,
    {
        let decoded = self.decode().map_err(ProofValidationError::input_data)?;
        let verification = decoded.verify_concealed(params).await?;
        Ok((decoded, verification))
    }

    /// Decodes, reveals and verify a compact SD-JWT.
    ///
    /// Only the registered JWT claims will be validated.
    /// If you need to validate custom claims, use the [`Self::reveal_verify`]
    /// method with `T` defining the custom claims.
    ///
    /// Returns the decoded JWT with the verification status.
    pub async fn decode_reveal_verify_any<P>(
        &self,
        params: P,
    ) -> Result<(RevealedSdJwt, Verification), ProofValidationError>
    where
        P: ResolverProvider<Resolver: JWKResolver> + DateTimeProvider,
    {
        let decoded = self.decode().map_err(ProofValidationError::input_data)?;
        decoded.reveal_verify_any(params).await
    }

    /// Decodes, reveals and verify a compact SD-JWT.
    ///
    /// Returns the decoded JWT with the verification status.
    pub async fn decode_reveal_verify<T, P>(
        &self,
        params: P,
    ) -> Result<(RevealedSdJwt<T>, Verification), ProofValidationError>
    where
        T: ClaimSet + DeserializeOwned + ValidateClaims<P, JWSSignature>,
        P: ResolverProvider<Resolver: JWKResolver> + DateTimeProvider,
    {
        let decoded = self.decode().map_err(ProofValidationError::input_data)?;
        decoded.reveal_verify(params).await
    }
}

impl AsRef<str> for SdJwt {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SdJwt {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Owned SD-JWT.
pub struct SdJwtBuf(Vec<u8>);

impl SdJwtBuf {
    /// Creates a new owned SD-JWT.
    pub fn new<B: BytesBuf>(bytes: B) -> Result<Self, InvalidDisclosure<B>> {
        if SdJwt::validate(bytes.as_ref()) {
            Ok(Self(bytes.into()))
        } else {
            Err(InvalidDisclosure(bytes))
        }
    }

    /// Creates a new owned SD-JWT without validating the input bytes.
    ///
    /// # Safety
    ///
    /// The input `bytes` **must** represent an SD-JWT.
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Conceals and sign the given claims.
    pub async fn conceal_and_sign(
        claims: &JWTClaims<impl Serialize>,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JWSSigner,
    ) -> Result<Self, SignatureError> {
        DecodedSdJwt::conceal_and_sign(claims, sd_alg, pointers, signer)
            .await
            .map(DecodedSdJwt::into_encoded)
    }

    /// Conceals and sign the given claims.
    pub async fn conceal_and_sign_with(
        claims: &JWTClaims<impl Serialize>,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JWSSigner,
        rng: impl CryptoRng + RngCore,
    ) -> Result<Self, SignatureError> {
        DecodedSdJwt::conceal_and_sign_with(claims, sd_alg, pointers, signer, rng)
            .await
            .map(DecodedSdJwt::into_encoded)
    }

    /// Borrows the SD-JWT.
    pub fn as_sd_jwt(&self) -> &SdJwt {
        unsafe { SdJwt::new_unchecked(&self.0) }
    }
}

impl Deref for SdJwtBuf {
    type Target = SdJwt;

    fn deref(&self) -> &Self::Target {
        self.as_sd_jwt()
    }
}

impl Borrow<SdJwt> for SdJwtBuf {
    fn borrow(&self) -> &SdJwt {
        self.as_sd_jwt()
    }
}

impl AsRef<SdJwt> for SdJwtBuf {
    fn as_ref(&self) -> &SdJwt {
        self.as_sd_jwt()
    }
}

impl AsRef<str> for SdJwtBuf {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SdJwtBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
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
    pub claims: serde_json::Map<String, Value>,
}

impl JWSPayload for SdJwtPayload {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl<E> ValidateJWSHeader<E> for SdJwtPayload {}

impl<E, P> ValidateClaims<E, P> for SdJwtPayload {}

/// Decoded SD-JWT.
pub struct DecodedSdJwt<'a> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: DecodedJWS<'a, SdJwtPayload>,

    /// Disclosures for associated JWT.
    pub disclosures: Vec<DecodedDisclosure<'a>>,
}

impl<'a> DecodedSdJwt<'a> {
    /// Verifies the decoded SD-JWT without revealing the concealed claims.
    ///
    /// No revealing the claims means only the registered JWT claims will be
    /// validated.
    pub async fn verify_concealed<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        P: ResolverProvider<Resolver: JWKResolver>,
    {
        self.jwt.verify(params).await
    }

    /// Verifies the decoded SD-JWT after revealing the claims.
    ///
    /// Only the registered JWT claims will be validated.
    /// If you need to validate custom claims, use the [`Self::reveal_verify`]
    /// method with `T` defining the custom claims.
    ///
    /// Returns the decoded JWT with the verification status.
    pub async fn reveal_verify_any<P>(
        self,
        params: P,
    ) -> Result<(RevealedSdJwt<'a>, Verification), ProofValidationError>
    where
        P: ResolverProvider<Resolver: JWKResolver> + DateTimeProvider,
    {
        let revealed = self
            .disclose_any()
            .map_err(ProofValidationError::input_data)?;
        let verification = revealed.verify(params).await?;
        Ok((revealed, verification))
    }

    /// Verifies the decoded SD-JWT after revealing the claims.
    ///
    /// The `T` type parameter is the type of private claims.
    pub async fn reveal_verify<T, P>(
        self,
        params: P,
    ) -> Result<(RevealedSdJwt<'a, T>, Verification), ProofValidationError>
    where
        T: ClaimSet + DeserializeOwned + ValidateClaims<P, JWSSignature>,
        P: ResolverProvider<Resolver: JWKResolver> + DateTimeProvider,
    {
        let revealed = self
            .disclose::<T>()
            .map_err(ProofValidationError::input_data)?;
        let verification = revealed.verify(params).await?;
        Ok((revealed, verification))
    }
}

impl DecodedSdJwt<'static> {
    /// Conceal and sign the given claims.
    pub async fn conceal_and_sign(
        claims: &JWTClaims<impl Serialize>,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JWSSigner,
    ) -> Result<Self, SignatureError> {
        let (payload, disclosures) =
            SdJwtPayload::conceal(claims, sd_alg, pointers).map_err(SignatureError::other)?;

        Ok(Self {
            jwt: signer.sign_into_decoded(payload).await?,
            disclosures,
        })
    }

    /// Conceal and sign the given claims with a custom rng.
    pub async fn conceal_and_sign_with(
        claims: &JWTClaims<impl Serialize>,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JWSSigner,
        rng: impl CryptoRng + RngCore,
    ) -> Result<Self, SignatureError> {
        let (payload, disclosures) = SdJwtPayload::conceal_with(claims, sd_alg, pointers, rng)
            .map_err(SignatureError::other)?;

        Ok(Self {
            jwt: signer.sign_into_decoded(payload).await?,
            disclosures,
        })
    }

    /// Encodes the SD-JWT.
    pub fn into_encoded(self) -> SdJwtBuf {
        let mut bytes = self.jwt.into_encoded().into_bytes();
        bytes.push(b'~');

        for d in self.disclosures {
            bytes.extend_from_slice(d.encoded.as_bytes());
            bytes.push(b'~');
        }

        unsafe {
            // SAFETY: we just constructed those bytes following the SD-JWT
            // syntax.
            SdJwtBuf::new_unchecked(bytes)
        }
    }
}

pub struct RevealedSdJwt<'a, T = AnyClaims> {
    pub jwt: DecodedJWT<'a, T>,
    pub disclosures: Vec<DecodedDisclosure<'a>>,
}

impl<'a, T> RevealedSdJwt<'a, T> {
    pub fn claims(&self) -> &JWTClaims<T> {
        &self.jwt.signing_bytes.payload
    }

    pub fn into_claims(self) -> JWTClaims<T> {
        self.jwt.signing_bytes.payload
    }

    pub async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        T: ClaimSet + ValidateClaims<P, JWSSignature>,
        P: ResolverProvider<Resolver: JWKResolver> + DateTimeProvider,
    {
        self.jwt.verify(params).await
    }
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
