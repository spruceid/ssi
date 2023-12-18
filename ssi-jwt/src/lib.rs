use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};

use chrono::{prelude::*, Duration, LocalResult};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{Error, Header};

// RFC 7519 - JSON Web Token (JWT)

pub fn encode_sign<Claims: Serialize>(
    algorithm: Algorithm,
    claims: &Claims,
    key: &JWK,
) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        type_: Some("JWT".to_string()),
        ..Default::default()
    };
    ssi_jws::encode_sign_custom_header(&payload, key, &header)
}

pub fn encode_unsigned<Claims: Serialize>(claims: &Claims) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    ssi_jws::encode_unsigned(&payload)
}

pub fn decode_verify<Claims: DeserializeOwned>(jwt: &str, key: &JWK) -> Result<Claims, Error> {
    let (_header, payload) = ssi_jws::decode_verify(jwt, key)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}

// for vc-test-suite
pub fn decode_unverified<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims, Error> {
    let (_header, payload) = ssi_jws::decode_unverified(jwt)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}

/// Represents NumericDate (see https://datatracker.ietf.org/doc/html/rfc7519#section-2)
/// where the range is restricted to those in which microseconds can be exactly represented,
/// which is approximately between the years 1685 and 2255, which was considered to be sufficient
/// for the purposes of this crate.  Note that leap seconds are ignored by this type, just as
/// they're ignored by NumericDate in the JWT standard.
///
/// An f64 value has 52 explicit mantissa bits, meaning that the biggest contiguous range
/// of integer values is from -2^53 to 2^53 (52 zeros after the mantissa's implicit 1).
/// Using this value to represent exact microseconds gives a maximum range of
///     +-2^53 / (1000000 * 60 * 60 * 24 * 365.25) ~= +-285,
/// which is centered around the Unix epoch start date Jan 1, 1970, 00:00:00 UTC, giving
/// the years 1685 to 2255.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, PartialOrd)]
pub struct NumericDate(#[serde(serialize_with = "interop_serialize")] f64);

/// As many JWT libraries only accept integers, this serializer aims for a
/// middle ground by serializing a date as an integer if it does not have
/// fractional seconds. Otherwise a trailing `.0` is always present.
fn interop_serialize<S>(x: &f64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if x.fract() != 0.0 {
        s.serialize_f64(*x)
    } else {
        s.serialize_i64(*x as i64)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NumericDateConversionError {
    #[error("Out of valid microsecond-precision range of NumericDate")]
    OutOfMicrosecondPrecisionRange,
}

impl NumericDate {
    /// This is -2^53 / 1_000_000, which is the smallest NumericDate that faithfully
    /// represents full microsecond precision.
    pub const MIN: NumericDate = NumericDate(-9_007_199_254.740_992);
    /// This is 2^53 / 1_000_000, which is the largest NumericDate that faithfully
    /// represents full microsecond precision.
    pub const MAX: NumericDate = NumericDate(9_007_199_254.740_992);

    /// Return the f64-valued number of seconds represented by this NumericDate.
    pub fn as_seconds(self) -> f64 {
        self.0
    }
    /// Try to create NumericDate from a f64 value, returning error upon out-of-range.
    pub fn try_from_seconds(seconds: f64) -> Result<Self, NumericDateConversionError> {
        if seconds.abs() > Self::MAX.0 {
            Err(NumericDateConversionError::OutOfMicrosecondPrecisionRange)
        } else {
            Ok(NumericDate(seconds))
        }
    }
    /// Decompose NumericDate for use in Utc.timestamp and Utc.timestamp_opt
    fn into_whole_seconds_and_fractional_nanoseconds(self) -> (i64, u32) {
        let whole_seconds = self.0.floor() as i64;
        let fractional_nanoseconds = ((self.0 - self.0.floor()) * 1_000_000_000.0).floor() as u32;
        assert!(fractional_nanoseconds < 1_000_000_000);
        (whole_seconds, fractional_nanoseconds)
    }
}

/// Note that this will panic if the addition goes out-of-range.
impl std::ops::Add<Duration> for NumericDate {
    type Output = NumericDate;
    fn add(self, rhs: Duration) -> Self::Output {
        let self_dtu: DateTime<Utc> = self.into();
        Self::Output::try_from(self_dtu + rhs).unwrap()
    }
}

/// Note that this will panic if the addition goes out-of-range.
impl std::ops::Sub<NumericDate> for NumericDate {
    type Output = Duration;
    fn sub(self, rhs: NumericDate) -> Self::Output {
        let self_dtu: DateTime<Utc> = self.into();
        let rhs_dtu: DateTime<Utc> = rhs.into();
        self_dtu - rhs_dtu
    }
}

/// Note that this will panic if the addition goes out-of-range.
impl std::ops::Sub<Duration> for NumericDate {
    type Output = NumericDate;
    fn sub(self, rhs: Duration) -> Self::Output {
        let self_dtu: DateTime<Utc> = self.into();
        Self::Output::try_from(self_dtu - rhs).unwrap()
    }
}

impl TryFrom<DateTime<Utc>> for NumericDate {
    type Error = NumericDateConversionError;
    fn try_from(dtu: DateTime<Utc>) -> Result<Self, Self::Error> {
        // Have to take seconds and nanoseconds separately in order to get the full allowable
        // range of microsecond-precision values as described above.
        let whole_seconds = dtu.timestamp() as f64;
        let fractional_seconds = dtu
            .timestamp_nanos_opt()
            .expect("value can not be represented in a timestamp with nanosecond precision.")
            .rem_euclid(1_000_000_000) as f64
            * 1.0e-9;
        Self::try_from_seconds(whole_seconds + fractional_seconds)
    }
}

impl TryFrom<DateTime<FixedOffset>> for NumericDate {
    type Error = NumericDateConversionError;
    fn try_from(dtfo: DateTime<FixedOffset>) -> Result<Self, Self::Error> {
        let dtu = DateTime::<Utc>::from(dtfo);
        NumericDate::try_from(dtu)
    }
}

impl From<NumericDate> for DateTime<Utc> {
    fn from(nd: NumericDate) -> Self {
        let (whole_seconds, fractional_nanoseconds) =
            nd.into_whole_seconds_and_fractional_nanoseconds();
        // `timestamp` (deprecated) was already doing an unwrap
        Utc.timestamp_opt(whole_seconds, fractional_nanoseconds)
            .unwrap()
    }
}

impl From<NumericDate> for LocalResult<DateTime<Utc>> {
    fn from(nd: NumericDate) -> Self {
        let (whole_seconds, fractional_nanoseconds) =
            nd.into_whole_seconds_and_fractional_nanoseconds();
        Utc.timestamp_opt(whole_seconds, fractional_nanoseconds)
    }
}
