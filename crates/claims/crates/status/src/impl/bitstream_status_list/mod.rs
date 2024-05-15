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

use crate::StatusMap;

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
    pub fn new(status_size: StatusSize) -> Self {
        Self {
            status_size,
            bytes: Vec::new(),
            len: 0,
        }
    }

    pub fn from_bytes(status_size: StatusSize, bytes: Vec<u8>) -> Self {
        let len = bytes.len() * 8usize / status_size.0 as usize;
        Self {
            status_size,
            bytes,
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);
        let high = self
            .bytes
            .get(offset.byte)?
            .overflowing_signed_shr(high_shift)
            .0;
        let low = match low_shift {
            Some(low_shift) => {
                self.bytes
                    .get(offset.byte + 1)?
                    .overflowing_shr(low_shift)
                    .0
            }
            None => 0,
        };
        Some((high | low) & self.status_size.mask())
    }

    pub fn set(&mut self, index: usize, value: u8) {
        let mask = self.status_size.mask();
        let value = value & mask;
        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        self.bytes[offset.byte] &= !mask.overflowing_signed_shl(high_shift).0; // clear high
        self.bytes[offset.byte] |= value.overflowing_signed_shl(high_shift).0; // set high
        if let Some(low_shift) = low_shift {
            self.bytes[offset.byte + 1] &= !mask.overflowing_shl(low_shift).0; // clear low
            self.bytes[offset.byte + 1] |= value.overflowing_shl(low_shift).0; // set low
        }
    }

    /// Push a new value into the bitstring.
    ///
    /// Only the low `status_size` bits will be pushed to the list.
    pub fn push(&mut self, value: u8) -> usize {
        let value = value & self.status_size.mask();
        let index = self.len;
        let offset = self.status_size.offset_of(index);

        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        if offset.byte == self.bytes.len() {
            self.bytes.push(value.overflowing_signed_shl(high_shift).0);
        } else {
            self.bytes[offset.byte] |= value.overflowing_signed_shl(high_shift).0
        }

        if let Some(low_shift) = low_shift {
            self.bytes.push(value.overflowing_shl(low_shift).0);
        }

        self.len += 1;
        index
    }

    pub fn iter(&self) -> BitStringIter {
        BitStringIter {
            bit_string: self,
            index: 0,
        }
    }

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

    pub fn len(&self) -> usize {
        self.bit_string.len()
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        self.bit_string.get(index)
    }

    pub fn set(&mut self, index: usize, value: u8) {
        self.bit_string.set(index, value)
    }

    pub fn push(&mut self, value: u8) -> usize {
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
            bit_string.push(s);
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
            bit_string.set(i, value);
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
}
