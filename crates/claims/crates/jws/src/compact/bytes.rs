use crate::{
    utils::is_url_safe_base64_char, DecodeError, DecodedJws, DecodedSigningBytes, Header,
    InvalidHeader, InvalidJws, JwsBuf, JwsSignature, JwsString,
};
pub use base64::DecodeError as Base64DecodeError;
use base64::Engine;
use ssi_claims_core::{ProofValidationError, ResolverProvider, Verification};
use ssi_jwk::JWKResolver;
use std::{borrow::Cow, ops::Deref};

/// Borrowed JWS without any encoding guaranties.
///
/// This is an unsized type borrowing the JWS and meant to be referenced as
/// `&JwsSlice`, just like `&[u8]`.
/// Use [`JwsVec`] if you need to own the JWS.
///
/// This type is similar to the [`Jws`](crate::Jws) type.
/// However contrarily to `Jws`, there is no guarantee that the JWS is a valid
/// UTF-8 string (and even less URL-safe).
///
/// Use [`JwsStr`](crate::JwsStr) if you expect UTF-8 encoded JWSs.
/// Use [`Jws`](crate::Jws) if you expect URL-safe JWSs.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct JwsSlice([u8]);

impl JwsSlice {
    pub fn new<T>(data: &T) -> Result<&Self, InvalidJws<&T>>
    where
        T: ?Sized + AsRef<[u8]>,
    {
        let bytes = data.as_ref();
        if Self::validate(bytes) {
            Ok(unsafe { Self::new_unchecked(bytes) })
        } else {
            Err(InvalidJws(data))
        }
    }

    /// Creates a new compact JWS without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must represent a valid compact JWS.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    pub const fn validate(bytes: &[u8]) -> bool {
        Self::validate_range(bytes, 0, bytes.len())
    }

    pub const fn validate_range(bytes: &[u8], mut i: usize, end: usize) -> bool {
        let mut j = if end > bytes.len() { bytes.len() } else { end };

        // Header.
        loop {
            if i >= j {
                // Missing `.`
                return false;
            }

            if bytes[i] == b'.' {
                break;
            }

            if !is_url_safe_base64_char(bytes[i]) {
                return false;
            }

            i += 1
        }

        // Signature.
        if i >= j {
            return false;
        }
        j -= 1;
        loop {
            if i >= j {
                // Missing `.`
                return false;
            }

            if bytes[j] == b'.' {
                break;
            }

            if !is_url_safe_base64_char(bytes[j]) {
                return false;
            }

            j -= 1
        }

        true
    }

    pub fn check_signing_bytes(bytes: &[u8]) -> bool {
        let mut i = 0;

        loop {
            if i >= bytes.len() {
                // Missing `.`
                break false;
            }

            if bytes[i] == b'.' {
                break true;
            }

            if !is_url_safe_base64_char(bytes[i]) {
                return false;
            }

            i += 1
        }
    }

    #[allow(clippy::len_without_is_empty)] // A JWS slice cannot be empty.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn header_end(&self) -> usize {
        self.0.iter().position(|b| *b == b'.').unwrap()
    }

    fn signature_start(&self) -> usize {
        self.0.len() - self.0.iter().rev().position(|b| *b == b'.').unwrap()
    }

    fn payload_start(&self) -> usize {
        self.header_end() + 1
    }

    pub(crate) fn payload_end(&self) -> usize {
        self.signature_start() - 1
    }

    /// Returns the Base64 encoded header.
    pub fn header(&self) -> &[u8] {
        &self.0[..self.header_end()]
    }

    pub fn decode_header(&self) -> Result<Header, InvalidHeader> {
        Header::decode(self.header())
    }

    /// Returns the Base64 encoded payload.
    pub fn payload(&self) -> &[u8] {
        &self.0[self.payload_start()..self.payload_end()]
    }

    /// Decode the payload bytes.
    ///
    /// The header is necessary to know how the payload is encoded.
    pub fn decode_payload(&self, header: &Header) -> Result<Cow<[u8]>, Base64DecodeError> {
        if header.base64urlencode_payload.unwrap_or(true) {
            Ok(Cow::Owned(
                base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(self.payload())?,
            ))
        } else {
            Ok(Cow::Borrowed(self.payload()))
        }
    }

    /// Returns the Base64 encoded signature.
    pub fn signature(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.0[self.signature_start()..]) }
    }

    pub fn decode_signature(&self) -> Result<JwsSignature, Base64DecodeError> {
        base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(self.signature())
            .map(JwsSignature::new)
    }

    /// Decodes the entire JWS.
    pub fn decode(&self) -> Result<DecodedJws<Cow<[u8]>>, DecodeError> {
        let header = self.decode_header().map_err(DecodeError::Header)?;
        let payload = self.decode_payload(&header).map_err(DecodeError::Payload)?;
        let signature = self.decode_signature().map_err(DecodeError::Signature)?;
        let signing_bytes = self.signing_bytes();

        Ok(DecodedJws::new(
            DecodedSigningBytes {
                bytes: Cow::Borrowed(signing_bytes),
                header,
                payload,
            },
            signature,
        ))
    }

    /// Returns the signing bytes.
    ///
    /// It is the concatenation of the Base64 encoded headers, a period '.' and
    /// the Base64 encoded payload.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.0[..self.payload_end()]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Verify the JWS signature.
    ///
    /// This will only check the signature and not the validity of the decoded
    /// payload. For instance if the payload is a set of JWT claims, those
    /// claims will not be validated.
    ///
    /// To perform a more precise verification, specify use a specialized `T`
    /// instead of the default [`Vec<u8>`]
    ///
    /// The `params` argument provides all the verification parameters required
    /// to validate the claims and proof.
    ///
    /// # What verification parameters should I use?
    ///
    /// Any type that providing a `JWKResolver` through the `ResolverProvider`
    /// trait will be fine. Notable implementors are:
    /// - [`VerificationParameters`](ssi_claims_core::VerificationParameters):
    ///   A good default providing many other common verification parameters that
    ///   are not necessary here.
    /// - [`JWK`](ssi_jwk::JWK): allows you to put a JWK as `params`, which
    ///   will resolve into itself. Can be useful if you don't need key resolution
    ///   because you know in advance what key was used to sign the JWS.
    ///
    /// # Passing the parameters by reference
    ///
    /// If the validation traits are implemented for `P`, they will be
    /// implemented for `&P` as well. This means the parameters can be passed
    /// by move *or* by reference.
    pub async fn verify<V>(&self, params: V) -> Result<Verification, ProofValidationError>
    where
        V: ResolverProvider,
        V::Resolver: JWKResolver,
    {
        let jws = self.decode().unwrap();
        jws.verify(params).await
    }
}

/// Owned JWS without any encoding guaranties.
///
/// This type is similar to the [`JwsBuf`](crate::JwsBuf) type.
/// However contrarily to `JwsBuf`, there is no guarantee that the JWS is a
/// valid UTF-8 string (and even less URL-safe).
///
/// Use [`JwsString`](crate::JwsString) if you expect UTF-8 encoded JWSs.
/// Use [`JwsBuf`](crate::JwsBuf) if you expect URL-safe JWSs.
pub struct JwsVec(Vec<u8>);

impl JwsVec {
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidJws<Vec<u8>>> {
        if JwsSlice::validate(&bytes) {
            Ok(Self(bytes))
        } else {
            Err(InvalidJws(bytes))
        }
    }

    /// # Safety
    ///
    /// The input `bytes` must represent a valid compact JWS.
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: &[u8],
    ) -> Result<Self, InvalidJws<Vec<u8>>> {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend_from_slice(signature);
        Self::new(bytes)
    }

    /// Creates a new detached JWS.
    ///
    /// Detached means the payload will not appear in the JWS.
    pub fn new_detached(header: Header, signature: &[u8]) -> Self {
        let mut bytes = header.encode().into_bytes();
        bytes.extend([b'.', b'.']);
        bytes.extend(signature.iter().copied());
        unsafe { Self::new_unchecked(bytes) }
    }

    /// # Safety
    ///
    /// The input `signing_bytes` and `signature` must form a valid compact JWS
    /// once concatenated with a `.`.
    pub unsafe fn from_signing_bytes_and_signature_unchecked(
        signing_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature);
        Self::new_unchecked(bytes)
    }

    pub fn as_compact_jws(&self) -> &JwsSlice {
        unsafe { JwsSlice::new_unchecked(&self.0) }
    }

    pub fn into_signing_bytes(mut self) -> Vec<u8> {
        self.0.truncate(self.payload_end()); // remove the signature.
        self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Decodes the entire JWS while preserving the signing bytes so they can
    /// be verified.
    pub fn into_decoded(self) -> Result<DecodedJws<'static>, DecodeError> {
        Ok(self.decode()?.into_owned())
    }

    pub fn into_url_safe(self) -> Result<JwsBuf, Self> {
        JwsBuf::new(self.0).map_err(|InvalidJws(bytes)| Self(bytes))
    }

    pub fn into_jws_string(self) -> Result<JwsString, Self> {
        JwsString::new(self.0).map_err(|InvalidJws(bytes)| Self(bytes))
    }
}

impl Deref for JwsVec {
    type Target = JwsSlice;

    fn deref(&self) -> &Self::Target {
        self.as_compact_jws()
    }
}
