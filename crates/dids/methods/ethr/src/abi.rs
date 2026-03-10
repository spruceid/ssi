use ssi_crypto::hashes::keccak;
use chrono::{DateTime, Utc};

// --- ERC-1056 ABI selectors ---

/// `changed(address)` — selector 0xf96d0f9f
pub(crate) const CHANGED_SELECTOR: [u8; 4] = [0xf9, 0x6d, 0x0f, 0x9f];

/// `identityOwner(address)` — selector 0x8733d4e8
pub(crate) const IDENTITY_OWNER_SELECTOR: [u8; 4] = [0x87, 0x33, 0xd4, 0xe8];

/// Encode a 20-byte address as a 32-byte ABI-padded word
pub(crate) fn abi_encode_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word
}

/// Build calldata: 4-byte selector + 32-byte padded address
pub(crate) fn encode_call(selector: [u8; 4], addr: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector);
    data.extend_from_slice(&abi_encode_address(addr));
    data
}

/// Decode a 32-byte uint256 return value
pub(crate) fn decode_uint256(data: &[u8]) -> u64 {
    if data.len() < 32 {
        return 0;
    }
    // Read last 8 bytes as u64 (ERC-1056 changed() returns small block numbers)
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[24..32]);
    u64::from_be_bytes(bytes)
}

/// Decode a 32-byte ABI-encoded address return value
pub(crate) fn decode_address(data: &[u8]) -> [u8; 20] {
    if data.len() < 32 {
        return [0u8; 20];
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&data[12..32]);
    addr
}

/// Convert raw 20 bytes to an EIP-55 checksummed hex address string
pub(crate) fn format_address_eip55(addr: &[u8; 20]) -> String {
    let lowercase = format!("0x{}", hex::encode(addr));
    keccak::eip55_checksum_addr(&lowercase).unwrap_or(lowercase)
}

/// Format a Unix timestamp (seconds since epoch) as ISO 8601 UTC string
pub(crate) fn format_timestamp_iso8601(unix_secs: u64) -> String {
    DateTime::<Utc>::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Compute keccak256 hash of an event signature string
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak::keccak256(data)
}
