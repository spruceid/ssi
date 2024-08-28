use std::io::{Read, Write};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use multibase::Base;
use serde::{Deserialize, Serialize};

mod status_list;
pub use status_list::*;

mod entry_set;
pub use entry_set::*;

/// Multibase-encoded base64url (with no padding) representation of the
/// GZIP-compressed bitstring values for the associated range of a bitstring
/// status list verifiable credential.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncodedList(String);

impl EncodedList {
    /// Minimum bitstring size (16KB).
    pub const MINIMUM_SIZE: usize = 16 * 1024;

    /// Default maximum bitstring size allowed by the `decode` function.
    ///
    /// 16MB.
    pub const DEFAULT_LIMIT: u64 = 16 * 1024 * 1024;

    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn encode(bytes: &[u8]) -> Self {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();

        // Add padding to satisfy the minimum bitstring size constraint.
        const PADDING_BUFFER_LEN: usize = 1024;
        let padding = [0; PADDING_BUFFER_LEN];
        let mut it = (bytes.len()..Self::MINIMUM_SIZE)
            .step_by(PADDING_BUFFER_LEN)
            .peekable();
        while let Some(start) = it.next() {
            let end = it.peek().copied().unwrap_or(Self::MINIMUM_SIZE);
            let len = end - start;
            encoder.write_all(&padding[..len]).unwrap();
        }

        let compressed = encoder.finish().unwrap();
        Self(multibase::encode(Base::Base64Url, compressed))
    }

    pub fn decode(&self, limit: Option<u64>) -> Result<Vec<u8>, DecodeError> {
        let limit = limit.unwrap_or(Self::DEFAULT_LIMIT);
        let (_base, compressed) = multibase::decode(&self.0)?;
        let mut decoder = GzDecoder::new(compressed.as_slice()).take(limit);
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes).map_err(DecodeError::Gzip)?;
        Ok(bytes)
    }
}
