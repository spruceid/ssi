use ssi_data_integrity::{AnySuite, DataIntegrity, DecodeError};

use super::JsonCredential;

/// Decodes a Data-Integrity credential or presentation from its JSON binary
/// representation.
pub fn any_credential_from_json_slice(
    json: &[u8],
) -> Result<DataIntegrity<JsonCredential, AnySuite>, DecodeError> {
    ssi_data_integrity::from_json_slice(json)
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub fn any_credential_from_json_str(
    json: &str,
) -> Result<DataIntegrity<JsonCredential, AnySuite>, DecodeError> {
    ssi_data_integrity::from_json_str(json)
}
