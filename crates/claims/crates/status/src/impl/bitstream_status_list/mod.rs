//! W3C Bitstring Status List v1.0
//!
//! A privacy-preserving, space-efficient, and high-performance mechanism for
//! publishing status information such as suspension or revocation of Verifiable
//! Credentials through use of bitstrings.
//!
//! See: <https://www.w3.org/TR/vc-bitstring-status-list/>
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use std::{hash::Hash, time::Duration};

use crate::{Overflow, StatusMap};

mod syntax;
pub use syntax::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusMessage {
    pub status: u8,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid status size `{0}`")]
pub struct InvalidStatusSize(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct StatusSize(u8);

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 8 {
            Ok(Self(value))
        } else {
            Err(InvalidStatusSize(value))
        }
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

#[derive(Debug, Serialize, Deserialize)]
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
    Message,
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

/// Bit-string as defined by the W3C Bitstring Status List specification.
///
/// Bits are indexed from most significant to least significant.
/// ```text
/// | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | ... | n-8 | n-7 | n-6 | n-5 | n-4 | n-3 | n-2 | n-1 |
/// | byte 0                        | ... | byte k-1                                      |
/// ```
///
/// See: <https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-encoding>
#[derive(Debug, Clone)]
pub struct BitString {
    status_size: StatusSize,
    bytes: Vec<u8>,
    len: usize,
}

impl BitString {
    /// Creates a new empty bit-string.
    pub fn new(status_size: StatusSize) -> Self {
        Self {
            status_size,
            bytes: Vec::new(),
            len: 0,
        }
    }

    /// Creates a bit-string from a byte array and status size.
    pub fn from_bytes(status_size: StatusSize, bytes: Vec<u8>) -> Self {
        let len = bytes.len() * 8usize / status_size.0 as usize;
        Self {
            status_size,
            bytes,
            len,
        }
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

        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        Some(self.get_at(offset.byte, high_shift, low_shift))
    }

    fn get_at(&self, byte_offset: usize, high_shift: i32, low_shift: Option<u32>) -> u8 {
        let high = self
            .bytes
            .get(byte_offset)
            .unwrap()
            .overflowing_signed_shr(high_shift)
            .0;

        let low = match low_shift {
            Some(low_shift) => {
                self.bytes
                    .get(byte_offset + 1)
                    .unwrap()
                    .overflowing_shr(low_shift)
                    .0
            }
            None => 0,
        };

        (high | low) & self.status_size.mask()
    }

    /// Sets the value at the given index.
    ///
    /// Returns the previous value, or an `Overflow` error if either the index
    /// is out of bounds or the value is too large.
    pub fn set(&mut self, index: usize, value: u8) -> Result<u8, Overflow> {
        if index >= self.len {
            return Err(Overflow::Index(index));
        }

        let mask = self.status_size.mask();
        let masked_value = value & mask;
        if masked_value != value {
            return Err(Overflow::Value(value));
        }

        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        let old_value = self.get_at(offset.byte, high_shift, low_shift);

        self.bytes[offset.byte] &= !mask.overflowing_signed_shl(high_shift).0; // clear high
        self.bytes[offset.byte] |= masked_value.overflowing_signed_shl(high_shift).0; // set high
        if let Some(low_shift) = low_shift {
            self.bytes[offset.byte + 1] &= !mask.overflowing_shl(low_shift).0; // clear low
            self.bytes[offset.byte + 1] |= masked_value.overflowing_shl(low_shift).0;
            // set low
        }

        Ok(old_value)
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

        if offset.byte == self.bytes.len() {
            self.bytes
                .push(masked_value.overflowing_signed_shl(high_shift).0);
        } else {
            self.bytes[offset.byte] |= masked_value.overflowing_signed_shl(high_shift).0
        }

        if let Some(low_shift) = low_shift {
            self.bytes.push(masked_value.overflowing_shl(low_shift).0);
        }

        self.len += 1;
        Ok(index)
    }

    /// Returns an iterator over all the statuses stored in this bit-string.
    pub fn iter(&self) -> BitStringIter {
        BitStringIter {
            bit_string: self,
            index: 0,
        }
    }

    /// Encodes the bit-string.
    pub fn encode(&self) -> EncodedList {
        EncodedList::encode(&self.bytes)
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

#[derive(Debug, Clone)]
pub struct StatusList {
    bit_string: BitString,
    ttl: TimeToLive,
}

impl StatusList {
    pub fn new(status_size: StatusSize, ttl: TimeToLive) -> Self {
        Self {
            bit_string: BitString::new(status_size),
            ttl,
        }
    }

    pub fn from_bytes(status_size: StatusSize, bytes: Vec<u8>, ttl: TimeToLive) -> Self {
        Self {
            bit_string: BitString::from_bytes(status_size, bytes),
            ttl,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bit_string.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bit_string.len()
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
        status_message: Vec<StatusMessage>,
    ) -> BitstringStatusList {
        BitstringStatusList::new(
            id,
            status_purpose,
            self.bit_string.status_size,
            self.bit_string.encode(),
            self.ttl,
            status_message,
        )
    }
}

pub struct BitStringIter<'a> {
    bit_string: &'a BitString,
    index: usize,
}

impl<'a> Iterator for BitStringIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.bit_string.get(self.index).map(|status| {
            self.index += 1;
            status
        })
    }
}

impl StatusMap for StatusList {
    type Key = usize;
    type Status = u8;

    fn time_to_live(&self) -> Option<Duration> {
        Some(self.ttl.into())
    }

    fn get_by_key(&self, key: Self::Key) -> Option<u8> {
        self.bit_string.get(key).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use crate::Overflow;

    use super::{BitString, StatusSize};

    fn random_bit_string(
        rng: &mut StdRng,
        status_size: StatusSize,
        len: usize,
    ) -> (Vec<u8>, BitString) {
        let mut values = Vec::with_capacity(len);

        for _ in 0..len {
            values.push((rng.next_u32() & 0xff) as u8 & status_size.mask())
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

        let encoded = bit_string.encode();
        let decoded = BitString::from_bytes(status_size, encoded.decode(None).unwrap());

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
}
