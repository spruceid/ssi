//! W3C Bitstring Status List v1.0 (Candidate Recommendation Draft 10 June 2024)
//!
//! A privacy-preserving, space-efficient, and high-performance mechanism for
//! publishing status information such as suspension or revocation of Verifiable
//! Credentials through use of bitstrings.
//!
//! See: <https://www.w3.org/TR/vc-bitstring-status-list/>
use core::fmt;
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use std::{hash::Hash, str::FromStr, time::Duration};

use crate::{Overflow, StatusMap, StatusSizeError};

mod syntax;
pub use syntax::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusMessage {
    #[serde(with = "prefixed_hexadecimal")]
    pub status: u8,
    pub message: String,
}

impl StatusMessage {
    pub fn new(status: u8, message: String) -> Self {
        Self { status, message }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid status size `{0}`")]
pub struct InvalidStatusSize(u8);

impl From<InvalidStatusSize> for StatusSizeError {
    fn from(_value: InvalidStatusSize) -> Self {
        Self::Invalid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct StatusSize(u8);

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (1..=8).contains(&value) {
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

impl Default for StatusSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl StatusSize {
    pub const DEFAULT: Self = Self(1);

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }

    fn offset_of(&self, index: usize) -> Offset {
        let bit_offset = self.0 as usize * index;
        Offset {
            byte: bit_offset / 8,
            bit: bit_offset % 8,
        }
    }

    fn last_of(&self, index: usize) -> Offset {
        let bit_offset = self.0 as usize * index + self.0 as usize - 1;
        Offset {
            byte: bit_offset / 8,
            bit: bit_offset % 8,
        }
    }

    fn mask(&self) -> u8 {
        if self.0 == 8 {
            0xff
        } else {
            (1 << self.0) - 1
        }
    }
}

impl<'de> Deserialize<'de> for StatusSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u8::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
struct Offset {
    byte: usize,
    bit: usize,
}

impl Offset {
    fn left_shift(&self, status_size: StatusSize) -> (i32, Option<u32>) {
        let high = (8 - status_size.0 as isize - self.bit as isize) as i32;
        let low = if high < 0 {
            Some((8 + high) as u32)
        } else {
            None
        };

        (high, low)
    }
}

/// Maximum duration, in milliseconds, an implementer is allowed to cache a
/// status list.
///
/// Default value is 300000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeToLive(pub u64);

impl Default for TimeToLive {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TimeToLive {
    pub const DEFAULT: Self = Self(300000);

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }
}

impl From<TimeToLive> for Duration {
    fn from(value: TimeToLive) -> Self {
        Duration::from_millis(value.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    /// Cancel the validity of a verifiable credential.
    ///
    /// This status is not reversible.
    Revocation,

    /// Temporarily prevent the acceptance of a verifiable credential.
    ///
    /// This status is reversible.
    Suspension,

    /// Convey an arbitrary message related to the status of the verifiable
    /// credential.
    ///
    /// The actual message is stored in the status list entry, in
    /// [`BitstringStatusListEntry::status_messages`].
    Message,
}

impl StatusPurpose {
    /// Creates a new status purpose from its name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "revocation" => Some(Self::Revocation),
            "suspension" => Some(Self::Suspension),
            "message" => Some(Self::Message),
            _ => None,
        }
    }

    /// Returns the name of this status purpose.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Suspension => "suspension",
            Self::Message => "message",
        }
    }

    /// Returns the string representation of this status purpose.
    ///
    /// Same as [`Self::name`].
    pub fn as_str(&self) -> &'static str {
        self.name()
    }

    /// Turns this status purpose into its name.
    ///
    /// Same as [`Self::name`].
    pub fn into_name(self) -> &'static str {
        self.name()
    }

    /// Turns this status purpose into its string representation.
    ///
    /// Same as [`Self::name`].
    pub fn into_str(self) -> &'static str {
        self.name()
    }
}

impl<'a> From<&'a StatusPurpose> for crate::StatusPurpose<&'a str> {
    fn from(value: &'a StatusPurpose) -> Self {
        match value {
            StatusPurpose::Revocation => Self::Revocation,
            StatusPurpose::Suspension => Self::Suspension,
            StatusPurpose::Message => Self::Other("message"),
        }
    }
}

impl<'a> PartialEq<crate::StatusPurpose<&'a str>> for StatusPurpose {
    fn eq(&self, other: &crate::StatusPurpose<&'a str>) -> bool {
        matches!(
            (self, other),
            (Self::Revocation, crate::StatusPurpose::Revocation)
                | (Self::Suspension, crate::StatusPurpose::Suspension)
                | (Self::Message, crate::StatusPurpose::Other("message"))
        )
    }
}

impl fmt::Display for StatusPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

/// Error raised when converting a string into a [`StatusPurpose`] fails.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid status purpose: {0}")]
pub struct InvalidStatusPurpose(pub String);

impl FromStr for StatusPurpose {
    type Err = InvalidStatusPurpose;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| InvalidStatusPurpose(s.to_owned()))
    }
}

/// Bit-string with status size.
///
///
/// This type is similar to [`BitString`] but also stores the bit size of
/// each item (status size) and the number of items in the list.
/// This provides a safer access to the underlying bit-string, ensuring that
/// status and list boundaries are respected.
#[derive(Debug, Clone)]
pub struct SizedBitString {
    inner: BitString,
    status_size: StatusSize,
    len: usize,
}

impl SizedBitString {
    /// Creates a new empty sized status list.
    pub fn new(status_size: StatusSize) -> Self {
        Self {
            inner: BitString::new(),
            status_size,
            len: 0,
        }
    }

    /// Creates a new bit-string of the given length, using `f` to initialize
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

    /// Creates a new bit-string of the given length, setting every status
    /// to the same value.
    pub fn new_with_value(
        status_size: StatusSize,
        len: usize,
        value: u8,
    ) -> Result<Self, Overflow> {
        Self::new_with(status_size, len, |_| value)
    }

    /// Creates a new bit-string of the given length, setting every status
    /// to 0.
    pub fn new_zeroed(status_size: StatusSize, len: usize) -> Self {
        Self::new_with_value(status_size, len, 0).unwrap() // 0 cannot overflow.
    }

    /// Creates a new bit-string with the given status size and capacity
    /// (in number of statuses).
    pub fn with_capacity(status_size: StatusSize, capacity: usize) -> Self {
        Self {
            inner: BitString::with_capacity(status_size, capacity),
            status_size,
            len: 0,
        }
    }

    /// Creates a bit-string from a byte array and status size.
    pub fn from_bytes(status_size: StatusSize, bytes: Vec<u8>) -> Self {
        let len = bytes.len() * 8usize / status_size.0 as usize;
        Self {
            inner: BitString::from_bytes(bytes),
            status_size,
            len,
        }
    }

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

    /// Returns the value stored in the list at the given index.
    pub fn get(&self, index: usize) -> Option<u8> {
        if index >= self.len {
            return None;
        }

        self.inner.get(self.status_size, index)
    }

    /// Push a new value into the bit-string.
    ///
    /// Returns the index of the newly inserted value in the list,
    /// or an error if the value is too large w.r.t. `status_size`.
    pub fn push(&mut self, value: u8) -> Result<usize, Overflow> {
        let masked_value = value & self.status_size.mask();
        if masked_value != value {
            return Err(Overflow::Value(value));
        }

        let index = self.len;
        let offset = self.status_size.offset_of(index);

        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        if offset.byte == self.inner.0.len() {
            self.inner
                .0
                .push(masked_value.overflowing_signed_shl(high_shift).0);
        } else {
            self.inner.0[offset.byte] |= masked_value.overflowing_signed_shl(high_shift).0
        }

        if let Some(low_shift) = low_shift {
            self.inner.0.push(masked_value.overflowing_shl(low_shift).0);
        }

        self.len += 1;
        Ok(index)
    }

    /// Sets the value at the given index.
    ///
    /// Returns the previous value, or an `Overflow` error if either the index
    /// is out of bounds or the value is too large.
    pub fn set(&mut self, index: usize, value: u8) -> Result<u8, Overflow> {
        if index >= self.len {
            return Err(Overflow::Index(index));
        }

        self.inner.set(self.status_size, index, value)
    }

    /// Returns an iterator over all the statuses stored in this bit-string.
    pub fn iter(&self) -> BitStringIter {
        self.inner.iter(self.status_size)
    }

    /// Encodes the bit-string.
    pub fn encode(&self) -> EncodedList {
        self.inner.encode()
    }

    pub fn into_unsized(self) -> BitString {
        self.inner
    }
}

/// Bit-string as defined by the W3C Bitstring Status List specification.
///
/// Bits are indexed from most significant to least significant.
/// ```text
/// | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | ... | n-8 | n-7 | n-6 | n-5 | n-4 | n-3 | n-2 | n-1 |
/// | byte 0                        | ... | byte k-1                                      |
/// ```
///
/// See: <https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-encoding>
///
/// This type does not store the actual status size (the size of each item)
/// nor the total number of items in the list. Use the [`SizedBitString`] type
/// to access the list safely with regard to the items boundaries.
#[derive(Debug, Default, Clone)]
pub struct BitString(Vec<u8>);

impl BitString {
    /// Creates a new empty bit-string.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new bit-string of the given length, using `f` to initialize
    /// every status.
    ///
    /// The `f` function is called with the index of the initialized status.
    pub fn new_with(
        status_size: StatusSize,
        len: usize,
        f: impl FnMut(usize) -> u8,
    ) -> Result<Self, Overflow> {
        SizedBitString::new_with(status_size, len, f).map(SizedBitString::into_unsized)
    }

    /// Creates a new bit-string of the given length, setting every status
    /// to the same value.
    pub fn new_with_value(
        status_size: StatusSize,
        len: usize,
        value: u8,
    ) -> Result<Self, Overflow> {
        Self::new_with(status_size, len, |_| value)
    }

    /// Creates a new bit-string of the given length, setting every status
    /// to 0.
    pub fn new_zeroed(status_size: StatusSize, len: usize) -> Self {
        Self::new_with_value(status_size, len, 0).unwrap() // 0 cannot overflow.
    }

    /// Creates a new bit-string with the given status size and capacity
    /// (in number of statuses).
    pub fn with_capacity(status_size: StatusSize, capacity: usize) -> Self {
        Self(Vec::with_capacity(
            (capacity * status_size.0 as usize).div_ceil(8),
        ))
    }

    /// Creates a bit-string from a byte array and status size.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the value stored in the list at the given index.
    pub fn get(&self, status_size: StatusSize, index: usize) -> Option<u8> {
        if status_size.last_of(index).byte >= self.0.len() {
            return None;
        }

        let offset = status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(status_size);

        Some(self.get_at(status_size, offset.byte, high_shift, low_shift))
    }

    fn get_at(
        &self,
        status_size: StatusSize,
        byte_offset: usize,
        high_shift: i32,
        low_shift: Option<u32>,
    ) -> u8 {
        let high = self
            .0
            .get(byte_offset)
            .unwrap()
            .overflowing_signed_shr(high_shift)
            .0;

        let low = match low_shift {
            Some(low_shift) => {
                self.0
                    .get(byte_offset + 1)
                    .unwrap()
                    .overflowing_shr(low_shift)
                    .0
            }
            None => 0,
        };

        (high | low) & status_size.mask()
    }

    /// Sets the value at the given index.
    ///
    /// Returns the previous value, or an `Overflow` error if either the index
    /// is out of bounds or the value is too large.
    pub fn set(
        &mut self,
        status_size: StatusSize,
        index: usize,
        value: u8,
    ) -> Result<u8, Overflow> {
        if status_size.last_of(index).byte >= self.0.len() {
            return Err(Overflow::Index(index));
        }

        let mask = status_size.mask();
        let masked_value = value & mask;
        if masked_value != value {
            return Err(Overflow::Value(value));
        }

        let offset = status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(status_size);

        let old_value = self.get_at(status_size, offset.byte, high_shift, low_shift);

        self.0[offset.byte] &= !mask.overflowing_signed_shl(high_shift).0; // clear high
        self.0[offset.byte] |= masked_value.overflowing_signed_shl(high_shift).0; // set high
        if let Some(low_shift) = low_shift {
            self.0[offset.byte + 1] &= !mask.overflowing_shl(low_shift).0; // clear low
            self.0[offset.byte + 1] |= masked_value.overflowing_shl(low_shift).0;
            // set low
        }

        Ok(old_value)
    }

    /// Returns an iterator over all the statuses stored in this bit-string.
    pub fn iter(&self, status_size: StatusSize) -> BitStringIter {
        BitStringIter {
            bit_string: self,
            status_size,
            index: 0,
        }
    }

    /// Encodes the bit-string.
    pub fn encode(&self) -> EncodedList {
        EncodedList::encode(&self.0)
    }
}

trait OverflowingSignedShift: Sized {
    fn overflowing_signed_shl(self, shift: i32) -> (Self, bool);

    fn overflowing_signed_shr(self, shift: i32) -> (Self, bool);
}

impl OverflowingSignedShift for u8 {
    fn overflowing_signed_shl(self, shift: i32) -> (u8, bool) {
        if shift < 0 {
            self.overflowing_shr(shift.unsigned_abs())
        } else {
            self.overflowing_shl(shift.unsigned_abs())
        }
    }

    fn overflowing_signed_shr(self, shift: i32) -> (u8, bool) {
        if shift < 0 {
            self.overflowing_shl(shift.unsigned_abs())
        } else {
            self.overflowing_shr(shift.unsigned_abs())
        }
    }
}

/// Status list.
///
/// This type does not store the actual status size (the size of each item)
/// nor the total number of items in the list. Use the [`SizedStatusList`] type
/// to access the list safely with regard to the items boundaries.
#[derive(Debug, Clone)]
pub struct StatusList {
    bit_string: BitString,
    ttl: TimeToLive,
}

impl StatusList {
    pub fn new(ttl: TimeToLive) -> Self {
        Self {
            bit_string: BitString::new(),
            ttl,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, ttl: TimeToLive) -> Self {
        Self {
            bit_string: BitString::from_bytes(bytes),
            ttl,
        }
    }

    pub fn get(&self, status_size: StatusSize, index: usize) -> Option<u8> {
        self.bit_string.get(status_size, index)
    }

    pub fn set(
        &mut self,
        status_size: StatusSize,
        index: usize,
        value: u8,
    ) -> Result<u8, Overflow> {
        self.bit_string.set(status_size, index, value)
    }

    pub fn iter(&self, status_size: StatusSize) -> BitStringIter {
        self.bit_string.iter(status_size)
    }

    pub fn to_credential_subject(
        &self,
        id: Option<UriBuf>,
        status_purpose: StatusPurpose,
    ) -> BitstringStatusList {
        BitstringStatusList::new(id, status_purpose, self.bit_string.encode(), self.ttl)
    }
}

/// Status list with status size.
///
/// This type is similar to [`StatusList`] but also stores the bit size of
/// each item (status size) and the number of items in the list.
/// This provides a safer access to the underlying bit-string, ensuring that
/// status and list boundaries are respected.
#[derive(Debug, Clone)]
pub struct SizedStatusList {
    bit_string: SizedBitString,
    ttl: TimeToLive,
}

impl SizedStatusList {
    pub fn new(status_size: StatusSize, ttl: TimeToLive) -> Self {
        Self {
            bit_string: SizedBitString::new(status_size),
            ttl,
        }
    }

    pub fn from_bytes(status_size: StatusSize, bytes: Vec<u8>, ttl: TimeToLive) -> Self {
        Self {
            bit_string: SizedBitString::from_bytes(status_size, bytes),
            ttl,
        }
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        self.bit_string.get(index)
    }

    pub fn set(&mut self, index: usize, value: u8) -> Result<u8, Overflow> {
        self.bit_string.set(index, value)
    }

    pub fn push(&mut self, value: u8) -> Result<usize, Overflow> {
        self.bit_string.push(value)
    }

    pub fn iter(&self) -> BitStringIter {
        self.bit_string.iter()
    }

    pub fn to_credential_subject(
        &self,
        id: Option<UriBuf>,
        status_purpose: StatusPurpose,
    ) -> BitstringStatusList {
        BitstringStatusList::new(id, status_purpose, self.bit_string.encode(), self.ttl)
    }

    pub fn into_unsized(self) -> StatusList {
        StatusList {
            bit_string: self.bit_string.into_unsized(),
            ttl: self.ttl,
        }
    }
}

pub struct BitStringIter<'a> {
    bit_string: &'a BitString,
    status_size: StatusSize,
    index: usize,
}

impl<'a> Iterator for BitStringIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.bit_string
            .get(self.status_size, self.index)
            .inspect(|_| {
                self.index += 1;
            })
    }
}

impl StatusMap for StatusList {
    type Key = usize;
    type StatusSize = StatusSize;
    type Status = u8;

    fn time_to_live(&self) -> Option<Duration> {
        Some(self.ttl.into())
    }

    fn get_by_key(
        &self,
        status_size: Option<StatusSize>,
        key: Self::Key,
    ) -> Result<Option<u8>, StatusSizeError> {
        Ok(self
            .bit_string
            .get(status_size.ok_or(StatusSizeError::Missing)?, key)
            .map(Into::into))
    }
}

mod prefixed_hexadecimal {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &u8, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("{value:#x}").serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let number = string
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("missing `0x` prefix"))?;
        u8::from_str_radix(number, 16).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use crate::Overflow;

    use super::{SizedBitString, StatusSize};

    fn random_bit_string(
        rng: &mut StdRng,
        status_size: StatusSize,
        len: usize,
    ) -> (Vec<u8>, SizedBitString) {
        let mut values = Vec::with_capacity(len);

        for _ in 0..len {
            values.push((rng.next_u32() & 0xff) as u8 & status_size.mask())
        }

        let mut bit_string = SizedBitString::new(status_size);
        for &s in &values {
            bit_string.push(s).unwrap();
        }

        (values, bit_string)
    }

    fn randomized_roundtrip(seed: u64, status_size: StatusSize, len: usize) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (values, bit_string) = random_bit_string(&mut rng, status_size, len);

        let encoded = bit_string.encode();
        let decoded = SizedBitString::from_bytes(status_size, encoded.decode(None).unwrap());

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
            let value = (rng.next_u32() & 0xff) as u8 & status_size.mask();
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
    fn randomized_roundtrip_3bits() {
        for i in 0..10 {
            randomized_roundtrip(i, 3u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 3u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 3u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_write_3bits() {
        for i in 0..10 {
            randomized_write(i, 3u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_write(i, 3u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_write(i, 3u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_roundtrip_7bits() {
        for i in 0..10 {
            randomized_roundtrip(i, 7u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 7u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_roundtrip(i, 7u8.try_into().unwrap(), 1000);
        }
    }

    #[test]
    fn randomized_write_7bits() {
        for i in 0..10 {
            randomized_write(i, 7u8.try_into().unwrap(), 10);
        }

        for i in 0..10 {
            randomized_write(i, 7u8.try_into().unwrap(), 100);
        }

        for i in 0..10 {
            randomized_write(i, 7u8.try_into().unwrap(), 1000);
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
    fn deserialize_status_size_3() {
        assert!(serde_json::from_str::<StatusSize>("3").is_ok())
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
