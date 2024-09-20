use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

mod credential;
pub use credential::*;

use crate::{
    bitstring_status_list::{StatusMessage, StatusPurpose, StatusSize},
    StatusMapEntry,
};

pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";

/// Bitstring status list entry.
///
/// References a particular entry of a status list, for a given status purpose.
/// It is the type of the `credentialStatus` property of a Verifiable
/// Credential.
///
/// See: <https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry>
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
    /// Optional identifier for the status list entry.
    ///
    /// Identifies the status information associated with the verifiable
    /// credential. Must *not* be the URL of the status list.
    pub id: Option<UriBuf>,

    /// Size of the status entry in bits.
    #[serde(default, skip_serializing_if = "StatusSize::is_default")]
    pub status_size: StatusSize,

    /// Purpose of the status entry.
    pub status_purpose: StatusPurpose,

    #[serde(
        rename = "statusMessage",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub status_messages: Vec<StatusMessage>,

    /// URL to material related to the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reference: Option<UriBuf>,

    /// URL to a `BitstringStatusListCredential` verifiable credential.
    pub status_list_credential: UriBuf,

    /// Arbitrary size integer greater than or equal to 0, encoded as a string
    /// in base 10.
    #[serde(with = "base10_nat_string")]
    pub status_list_index: usize,
}

impl BitstringStatusListEntry {
    /// Creates a new bit-string status list entry.
    pub fn new(
        id: Option<UriBuf>,
        status_size: StatusSize,
        status_purpose: StatusPurpose,
        status_messages: Vec<StatusMessage>,
        status_list_credential: UriBuf,
        status_list_index: usize,
    ) -> Self {
        Self {
            id,
            status_size,
            status_purpose,
            status_messages,
            status_reference: None,
            status_list_credential,
            status_list_index,
        }
    }
}

impl StatusMapEntry for BitstringStatusListEntry {
    type Key = usize;
    type StatusSize = StatusSize;

    fn status_list_url(&self) -> &Uri {
        &self.status_list_credential
    }

    fn key(&self) -> Self::Key {
        self.status_list_index
    }

    fn status_size(&self) -> Option<Self::StatusSize> {
        Some(self.status_size)
    }
}

mod base10_nat_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(n: &usize, serializer: S) -> Result<S::Ok, S::Error> {
        n.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<usize, D::Error> {
        let string = String::deserialize(deserializer)?;
        string.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::BitstringStatusListEntry;
    use crate::bitstring_status_list::{StatusMessage, StatusPurpose};

    const ENTRY: &str = r#"{
        "id": "https://example.com/credentials/status/8#492847",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "message",
        "statusListIndex": "492847",
        "statusSize": 2,
        "statusListCredential": "https://example.com/credentials/status/8",
        "statusMessage": [
            {"status":"0x0", "message":"pending_review"},
            {"status":"0x1", "message":"accepted"},
            {"status":"0x2", "message":"rejected"}
        ],
        "statusReference": "https://example.org/status-dictionary/"
    }"#;

    #[test]
    fn deserialize() {
        serde_json::from_str::<BitstringStatusListEntry>(ENTRY).unwrap();
    }

    #[test]
    fn serialize() {
        let expected: serde_json::Value = serde_json::from_str(ENTRY).unwrap();

        let status_list = BitstringStatusListEntry {
            id: Some(
                "https://example.com/credentials/status/8#492847"
                    .parse()
                    .unwrap(),
            ),
            status_size: 2.try_into().unwrap(),
            status_purpose: StatusPurpose::Message,
            status_list_index: 492847,
            status_messages: vec![
                StatusMessage::new(0, "pending_review".to_owned()),
                StatusMessage::new(1, "accepted".to_owned()),
                StatusMessage::new(2, "rejected".to_owned()),
            ],
            status_list_credential: "https://example.com/credentials/status/8".parse().unwrap(),
            status_reference: Some("https://example.org/status-dictionary/".parse().unwrap()),
        };

        let value = serde_json::to_value(status_list).unwrap();
        assert_eq!(value, expected);
    }
}
