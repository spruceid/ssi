//! IETF Token Status List.
//!
//! A Token Status List provides a way to represent the status
//! of tokens secured by JSON Object Signing and Encryption (JOSE) or CBOR
//! Object Signing and Encryption (COSE). Such tokens can include JSON Web
//! Tokens (JWTs), CBOR Web Tokens (CWTs) and ISO mdoc.
//!
//! Token status lists are themselves encoded as JWTs or CWTs.
//!
//! See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html>
use flate2::{bufread::ZlibDecoder, write::ZlibEncoder, Compression};
use iref::Uri;
use serde::Serialize;
use ssi_claims_core::{DateTimeProvider, ResolverProvider};
use std::{
    io::{self, Read, Write},
    time::Duration,
};

pub mod cbor;
pub mod json;

pub use json::StatusListJwt;
use ssi_jwk::JWKResolver;
use ssi_jws::{InvalidJws, JwsSlice};
use ssi_jwt::{ClaimSet, InvalidClaimValue, JWTClaims, ToDecodedJwt};

use crate::{
    EncodedStatusMap, FromBytes, FromBytesOptions, Overflow, StatusMap, StatusMapEntry,
    StatusMapEntrySet, StatusSizeError,
};

/// Status value describing a Token that is valid, correct or legal.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-7.1>
pub const VALID: u8 = 0;

/// Status value describing a Token that is revoked, annulled, taken back,
/// recalled or cancelled.
///
/// This state is irreversible.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-7.1>
pub const INVALID: u8 = 1;

/// Status value describing a Token that is temporarily invalid, hanging,
/// debarred from privilege.
///
/// This state is reversible.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-7.1>
pub const SUSPENDED: u8 = 2;

/// Token Status List, serialized as a JWT or CWT.
pub enum StatusListToken {
    Jwt(StatusListJwt),
}

impl StatusListToken {
    pub fn decode_status_list(self) -> Result<StatusList, DecodeError> {
        match self {
            Self::Jwt(claims) => json::decode_status_list_jwt(claims),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    #[error("missing media type")]
    MissingMediaType,

    #[error("unexpected media type `{0}`")]
    UnexpectedMediaType(String),

    #[error(transparent)]
    JWS(#[from] InvalidJws<Vec<u8>>),

    #[error("invalid JWT: {0}")]
    JWT(#[from] ssi_jwt::DecodeError),

    #[error("unexpected JWS type `{0}`")]
    UnexpectedJWSType(String),

    #[error("missing JWS type")]
    MissingJWSType,

    #[error("proof preparation failed: {0}")]
    Preparation(#[from] ssi_claims_core::ProofPreparationError),

    #[error("proof verification failed: {0}")]
    Verification(#[from] ssi_claims_core::ProofValidationError),

    #[error(transparent)]
    Rejected(#[from] ssi_claims_core::Invalid),
}

impl<V> FromBytes<V> for StatusListToken
where
    V: ResolverProvider + DateTimeProvider,
    V::Resolver: JWKResolver,
{
    type Error = FromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verifier: &V,
        _options: FromBytesOptions,
    ) -> Result<Self, Self::Error> {
        match media_type {
            "statuslist+jwt" => {
                let jwt = JwsSlice::new(bytes)
                    .map_err(InvalidJws::into_owned)?
                    .to_decoded_custom_jwt::<json::StatusListJwtPrivateClaims>()?;

                match jwt.signing_bytes.header.type_.as_deref() {
                    Some("statuslist+jwt") => {
                        jwt.verify(verifier).await??;
                        Ok(Self::Jwt(jwt.signing_bytes.payload))
                    }
                    Some(other) => Err(FromBytesError::UnexpectedJWSType(other.to_owned())),
                    None => Err(FromBytesError::MissingJWSType),
                }
            }
            "statuslist+cwt" => {
                todo!()
            }
            other => Err(FromBytesError::UnexpectedMediaType(other.to_owned())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid claim: {0}")]
    Claim(String),

    #[error("missing issuer")]
    MissingIssuer,

    #[error("missing subject")]
    MissingSubject,

    #[error("missing `status_list` claim")]
    MissingStatusList,

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("ZLIB decompression: {0}")]
    Zlib(#[from] io::Error),
}

impl DecodeError {
    pub fn claim(e: impl ToString) -> Self {
        Self::Claim(e.to_string())
    }
}

impl EncodedStatusMap for StatusListToken {
    type Decoded = StatusList;
    type DecodeError = DecodeError;

    fn decode(self) -> Result<Self::Decoded, Self::DecodeError> {
        self.decode_status_list()
    }
}

/// Type of a JWT representing a status list.
///
/// This is the required value of the JWT Header's `typ` field.
pub const JWT_TYPE: &str = "statuslist+jwt";

#[derive(Debug, thiserror::Error)]
#[error("invalid status size {0}")]
pub struct InvalidStatusSize(u8);

impl From<InvalidStatusSize> for StatusSizeError {
    fn from(_value: InvalidStatusSize) -> Self {
        Self::Invalid
    }
}

/// Number of bits per Referenced Token in a Status List.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StatusSize(u8);

impl StatusSize {
    /// Returns the number of statuses per status list byte.
    pub const fn status_per_byte(&self) -> usize {
        8 / self.0 as usize
    }

    /// Returns the bit-mask necessary to extract a status.
    pub const fn status_mask(&self) -> u8 {
        match self.0 {
            1 => 0b1,
            2 => 0b11,
            4 => 0b1111,
            _ => 0b11111111,
        }
    }

    /// Returns the byte index storing the given status index in a status list
    /// with this status size, along with the intra-byte offset.
    pub const fn offset_of(&self, index: usize) -> (usize, usize) {
        let spb = self.status_per_byte();
        (index / spb, (index % spb) * self.0 as usize)
    }
}

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if matches!(value, 1 | 2 | 4 | 8) {
            Ok(Self(value))
        } else {
            Err(InvalidStatusSize(value))
        }
    }
}

impl From<StatusSize> for u8 {
    fn from(value: StatusSize) -> Self {
        value.0
    }
}

impl<'de> serde::Deserialize<'de> for StatusSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u8::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
pub struct StatusList {
    bit_string: BitString,
    ttl: Option<u64>,
}

impl StatusList {
    pub fn new(bit_string: BitString, ttl: Option<u64>) -> Self {
        Self { bit_string, ttl }
    }

    pub fn iter(&self) -> BitStringIter {
        self.bit_string.iter()
    }
}

impl StatusMap for StatusList {
    type Key = usize;
    type StatusSize = StatusSize;
    type Status = u8;

    fn time_to_live(&self) -> Option<Duration> {
        self.ttl.map(Duration::from_secs)
    }

    fn get_by_key(
        &self,
        _status_size: Option<StatusSize>,
        key: Self::Key,
    ) -> Result<Option<Self::Status>, StatusSizeError> {
        Ok(self.bit_string.get(key))
    }
}

/// Status List.
///
/// A Status List is a byte array that contains the statuses of many
/// Referenced Tokens represented by one or multiple bits.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-4>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitString {
    status_size: StatusSize,
    bytes: Vec<u8>,
    len: usize,
}

impl BitString {
    /// Default maximum bitstring size allowed by the `from_compressed_bytes` function.
    ///
    /// 16MB.
    pub const DEFAULT_LIMIT: u64 = 16 * 1024 * 1024;

    /// Creates a new status list with the given status size.
    pub fn new(status_size: StatusSize) -> Self {
        Self {
            status_size,
            bytes: Vec::new(),
            len: 0,
        }
    }

    /// Creates a new status list of the given length, using `f` to initialize
    /// every status.
    ///
    /// The `f` function is called with the index of the initialized status.
    pub fn new_with(
        status_size: StatusSize,
        len: usize,
        mut f: impl FnMut(usize) -> u8,
    ) -> Result<Self, Overflow> {
        let mut result = Self::with_capacity(status_size, len);

        for i in 0..len {
            result.push(f(i))?;
        }

        Ok(result)
    }

    /// Creates a new status list of the given length, setting every status
    /// to the same value.
    pub fn new_with_value(
        status_size: StatusSize,
        len: usize,
        value: u8,
    ) -> Result<Self, Overflow> {
        Self::new_with(status_size, len, |_| value)
    }

    /// Creates a new status list of the given length, setting every status
    /// to 0.
    ///
    /// This is an alias for [`Self::new_valid`].
    pub fn new_zeroed(status_size: StatusSize, len: usize) -> Self {
        Self::new_valid(status_size, len)
    }

    /// Creates a new status list of the given length, setting every status
    /// to [`VALID`].
    pub fn new_valid(status_size: StatusSize, len: usize) -> Self {
        Self::new_with_value(status_size, len, VALID).unwrap() // `VALID` cannot overflow.
    }

    /// Creates a new status list of the given length, setting every status
    /// to [`INVALID`].
    pub fn new_invalid(status_size: StatusSize, len: usize) -> Self {
        Self::new_with_value(status_size, len, INVALID).unwrap() // `INVALID` cannot overflow.
    }

    /// Creates a new status list with the given status size and capacity
    /// (in number of statuses).
    pub fn with_capacity(status_size: StatusSize, capacity: usize) -> Self {
        Self {
            status_size,
            bytes: Vec::with_capacity(capacity.div_ceil(status_size.status_per_byte())),
            len: 0,
        }
    }

    /// Creates a new status list from a status size and byte array.
    pub fn from_parts(status_size: StatusSize, data: Vec<u8>) -> Self {
        let len = data.len() * 8usize / status_size.0 as usize;
        Self {
            status_size,
            bytes: data,
            len,
        }
    }

    /// Decompress a bit-string using DEFLATE ([RFC1951]) with the ZLIB
    /// ([RFC1950]) data format.
    ///
    /// [RFC1951]: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#RFC1951>
    /// [RFC1950]: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#RFC1950>
    pub fn from_compressed_bytes(
        status_size: StatusSize,
        bytes: &[u8],
        limit: Option<u64>,
    ) -> Result<Self, io::Error> {
        let limit = limit.unwrap_or(Self::DEFAULT_LIMIT);
        let mut decoder = ZlibDecoder::new(bytes).take(limit);
        let mut buffer = Vec::new();
        decoder.read_to_end(&mut buffer)?;
        Ok(Self::from_parts(status_size, buffer))
    }

    /// Returns the status bit-size.
    pub fn status_size(&self) -> StatusSize {
        self.status_size
    }

    /// Checks if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the length of the list (number of statuses).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `index`-th status in the list.
    pub fn get(&self, index: usize) -> Option<u8> {
        if index < self.len {
            let (a, b) = self.status_size.offset_of(index);
            Some((self.bytes[a] >> b) & self.status_size.status_mask())
        } else {
            None
        }
    }

    /// Sets the value at the given index.
    ///
    /// Returns the previous value, or an `Overflow` error if either the index
    /// is out of bounds or the value is too large.
    pub fn set(&mut self, index: usize, value: u8) -> Result<u8, Overflow> {
        if index >= self.len {
            return Err(Overflow::Index(index));
        }

        let status_mask = self.status_size.status_mask();
        let masked_value = value & status_mask;

        if masked_value != value {
            return Err(Overflow::Value(value));
        }

        let (a, b) = self.status_size.offset_of(index);

        let old_value = (self.bytes[a] >> b) & status_mask;
        self.bytes[a] &= !(status_mask << b); // clear
        self.bytes[a] |= masked_value << b; // set

        Ok(old_value)
    }

    /// Push a new value into the bit-string.
    ///
    /// Returns the index of the newly inserted value in the list,
    /// or an error if the value is too large w.r.t. `status_size`.
    pub fn push(&mut self, value: u8) -> Result<usize, Overflow> {
        let status_mask = self.status_size.status_mask();
        let masked_value = value & status_mask;

        if masked_value != value {
            return Err(Overflow::Value(value));
        }

        let index = self.len;
        self.len += 1;
        let (a, b) = self.status_size.offset_of(index);

        if a == self.bytes.len() {
            self.bytes.push(masked_value << b)
        } else {
            self.bytes[a] |= masked_value << b
        }

        Ok(a)
    }

    /// Returns this bit-string as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Compress the bit-string using DEFLATE ([RFC1951]) with the ZLIB
    /// ([RFC1950]) data format.
    ///
    /// [RFC1951]: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#RFC1951>
    /// [RFC1950]: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#RFC1950>
    pub fn to_compressed_bytes(&self, compression: Compression) -> Vec<u8> {
        let mut buffer = Vec::new();

        {
            let mut encoder = ZlibEncoder::new(&mut buffer, compression);

            encoder.write_all(&self.bytes).unwrap();
        }

        buffer
    }

    /// Returns an iterator over all the statuses stored in this bit-string.
    pub fn iter(&self) -> BitStringIter {
        BitStringIter {
            bit_string: self,
            index: 0,
        }
    }

    /// Consumes the bit-string and returns the status size and underlying
    /// byte array.
    pub fn into_parts(self) -> (StatusSize, Vec<u8>) {
        (self.status_size, self.bytes)
    }
}

pub struct BitStringIter<'a> {
    bit_string: &'a BitString,
    index: usize,
}

impl<'a> Iterator for BitStringIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.bit_string.get(self.index).inspect(|_| {
            self.index += 1;
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EntrySetFromBytesError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    JWS(#[from] InvalidJws<Vec<u8>>),

    #[error(transparent)]
    JWT(#[from] ssi_jwt::DecodeError),

    #[error(transparent)]
    ClaimValue(#[from] InvalidClaimValue),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(#[from] ssi_claims_core::ProofPreparationError),

    #[error("proof validation failed: {0}")]
    ProofValidation(#[from] ssi_claims_core::ProofValidationError),

    #[error("rejected claims: {0}")]
    Rejected(#[from] ssi_claims_core::Invalid),

    #[error("missing status")]
    MissingStatus,
}

pub enum AnyStatusListEntrySet {
    Json(json::Status),
}

impl<V> FromBytes<V> for AnyStatusListEntrySet
where
    V: ResolverProvider + DateTimeProvider,
    V::Resolver: JWKResolver,
{
    type Error = EntrySetFromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verifier: &V,
        _options: FromBytesOptions,
    ) -> Result<Self, EntrySetFromBytesError> {
        match media_type {
            "application/json" => {
                let claims: JWTClaims = serde_json::from_slice(bytes)?;
                Ok(Self::Json(
                    claims
                        .try_get::<json::Status>()?
                        .ok_or(EntrySetFromBytesError::MissingStatus)?
                        .into_owned(),
                ))
            }
            "application/jwt" => {
                let jwt = JwsSlice::new(bytes)
                    .map_err(InvalidJws::into_owned)?
                    .to_decoded_jwt()?;
                jwt.verify(verifier).await??;

                Ok(Self::Json(
                    jwt.signing_bytes
                        .payload
                        .try_get::<json::Status>()?
                        .ok_or(EntrySetFromBytesError::MissingStatus)?
                        .into_owned(),
                ))
            }
            // "application/cbor" => {
            //     // ...
            // },
            // "application/cwt" => {
            //     // ...
            // },
            _ => todo!(),
        }
    }
}

impl StatusMapEntrySet for AnyStatusListEntrySet {
    type Entry<'a> = AnyStatusListReference<'a> where Self: 'a;

    fn get_entry(&self, purpose: crate::StatusPurpose<&str>) -> Option<Self::Entry<'_>> {
        match self {
            Self::Json(s) => s.get_entry(purpose).map(AnyStatusListReference::Json),
        }
    }
}

pub enum AnyStatusListReference<'a> {
    Json(&'a json::StatusListReference),
}

impl<'a> StatusMapEntry for AnyStatusListReference<'a> {
    type Key = usize;
    type StatusSize = StatusSize;

    fn key(&self) -> Self::Key {
        match self {
            Self::Json(e) => e.key(),
        }
    }

    fn status_list_url(&self) -> &Uri {
        match self {
            Self::Json(e) => e.status_list_url(),
        }
    }

    fn status_size(&self) -> Option<Self::StatusSize> {
        match self {
            Self::Json(e) => e.status_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use crate::Overflow;

    use super::{json::JsonStatusList, BitString, StatusSize};

    fn random_bit_string(
        rng: &mut StdRng,
        status_size: StatusSize,
        len: usize,
    ) -> (Vec<u8>, BitString) {
        let mut values = Vec::with_capacity(len);

        for _ in 0..len {
            values.push((rng.next_u32() & 0xff) as u8 & status_size.status_mask())
        }

        let mut bit_string = BitString::new(status_size);
        for &s in &values {
            bit_string.push(s).unwrap();
        }

        (values, bit_string)
    }

    fn randomized_roundtrip(seed: u64, status_size: StatusSize, len: usize) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (values, bit_string) = random_bit_string(&mut rng, status_size, len);

        let encoded = JsonStatusList::encode(&bit_string, Compression::fast());
        let decoded = encoded.decode(None).unwrap();

        assert!(decoded.len() >= len);

        for i in 0..len {
            assert_eq!(decoded.get(i), Some(values[i]))
        }
    }

    fn randomized_write(seed: u64, status_size: StatusSize, len: usize) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (mut values, mut bit_string) = random_bit_string(&mut rng, status_size, len);

        for _ in 0..len {
            let i = (rng.next_u32() as usize) % len;
            let value = (rng.next_u32() & 0xff) as u8 & status_size.status_mask();
            bit_string.set(i, value).unwrap();
            values[i] = value;
        }

        for i in 0..len {
            assert_eq!(bit_string.get(i), Some(values[i]))
        }
    }

    #[test]
    fn randomized_roundtrip_1bit() {
        for i in 0..10 {
            randomized_roundtrip(i, 1u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 1u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 1u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_write_1bits() {
        for i in 0..10 {
            randomized_write(i, 1u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_write(i, 1u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_write(i, 1u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_roundtrip_2bits() {
        for i in 0..10 {
            randomized_roundtrip(i, 2u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 2u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 2u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_write_2bits() {
        for i in 0..10 {
            randomized_write(i, 2u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_write(i, 2u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_write(i, 2u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_roundtrip_4bits() {
        for i in 0..10 {
            randomized_roundtrip(i, 4u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 4u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 4u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_write_4bits() {
        for i in 0..10 {
            randomized_write(i, 4u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_write(i, 4u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_write(i, 4u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn overflows() {
        let mut rng = StdRng::seed_from_u64(0);
        let (_, mut bitstring) = random_bit_string(&mut rng, 1u8.try_into().unwrap(), 15);

        // Out of bounds.
        assert!(bitstring.get(15).is_none());

        // Out of bounds (even if there are enough bytes in the list).
        assert_eq!(bitstring.set(15, 0), Err(Overflow::Index(15)));

        // Too many bits.
        assert_eq!(bitstring.set(14, 2), Err(Overflow::Value(2)));
    }

    #[test]
    fn deserialize_status_size_1() {
        assert!(serde_json::from_str::<StatusSize>("1").is_ok())
    }

    #[test]
    fn deserialize_status_size_2() {
        assert!(serde_json::from_str::<StatusSize>("2").is_ok())
    }

    #[test]
    fn deserialize_status_size_4() {
        assert!(serde_json::from_str::<StatusSize>("4").is_ok())
    }

    #[test]
    fn deserialize_status_size_8() {
        assert!(serde_json::from_str::<StatusSize>("8").is_ok())
    }

    #[test]
    fn deserialize_status_size_non_power_of_two() {
        assert!(serde_json::from_str::<StatusSize>("3").is_err())
    }

    #[test]
    fn deserialize_status_size_negative() {
        assert!(serde_json::from_str::<StatusSize>("-1").is_err())
    }

    #[test]
    fn deserialize_status_size_overflow() {
        assert!(serde_json::from_str::<StatusSize>("9").is_err())
    }
}
