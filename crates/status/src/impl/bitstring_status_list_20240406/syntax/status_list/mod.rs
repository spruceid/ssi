use iref::UriBuf;
use serde::{Deserialize, Serialize};

mod credential;
pub use credential::*;

use crate::bitstring_status_list_20240406::{
    EncodedList, StatusList, StatusMessage, StatusPurpose, StatusSize, TimeToLive,
};

pub const BITSTRING_STATUS_LIST_TYPE: &str = "BitstringStatusList";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct BitstringStatusList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Status purpose.
    pub status_purpose: StatusPurpose,

    #[serde(default, skip_serializing_if = "StatusSize::is_default")]
    pub status_size: StatusSize,

    /// Encoded status list.
    pub encoded_list: EncodedList,

    /// Time to live.
    #[serde(default, skip_serializing_if = "TimeToLive::is_default")]
    pub ttl: TimeToLive,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_message: Vec<StatusMessage>,

    /// URL to material related to the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reference: Option<UriBuf>,
}

impl BitstringStatusList {
    pub fn new(
        id: Option<UriBuf>,
        status_purpose: StatusPurpose,
        status_size: StatusSize,
        encoded_list: EncodedList,
        ttl: TimeToLive,
        status_message: Vec<StatusMessage>,
    ) -> Self {
        Self {
            id,
            status_purpose,
            status_size,
            encoded_list,
            ttl,
            status_message,
            status_reference: None,
        }
    }

    pub fn decode(&self) -> Result<StatusList, DecodeError> {
        let bytes = self.encoded_list.decode(None)?;
        Ok(StatusList::from_bytes(self.status_size, bytes, self.ttl))
    }
}

#[cfg(test)]
mod tests {
    use super::BitstringStatusList;
    use crate::bitstring_status_list_20240406::{
        EncodedList, StatusMessage, StatusPurpose, TimeToLive,
    };

    const STATUS_LIST: &str = r#"{
        "id": "https://example.com/status/3#list",
        "type": "BitstringStatusList",
        "ttl": 500,
        "statusPurpose": "message",
        "statusReference": "https://example.org/status-dictionary/",
        "statusSize": 2,
        "statusMessage": [
            {"status":"0x0", "message":"valid"},
            {"status":"0x1", "message":"invalid"},
            {"status":"0x2", "message":"pending_review"}
        ],
        "encodedList": "uH4sIAAAAAAAAA-3BMQEAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
    }"#;

    #[test]
    fn deserialize() {
        serde_json::from_str::<BitstringStatusList>(STATUS_LIST).unwrap();
    }

    #[test]
    fn serialize() {
        let expected: serde_json::Value = serde_json::from_str(STATUS_LIST).unwrap();

        let status_list = BitstringStatusList {
            id: Some("https://example.com/status/3#list".parse().unwrap()),
            ttl: TimeToLive(500),
            status_purpose: StatusPurpose::Message,
            status_reference: Some("https://example.org/status-dictionary/".parse().unwrap()),
            status_size: 2.try_into().unwrap(),
            status_message: vec![
                StatusMessage::new(0, "valid".to_owned()),
                StatusMessage::new(1, "invalid".to_owned()),
                StatusMessage::new(2, "pending_review".to_owned()),
            ],
            encoded_list: EncodedList::new(
                "uH4sIAAAAAAAAA-3BMQEAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA".to_owned(),
            ),
        };

        let value = serde_json::to_value(status_list).unwrap();
        assert_eq!(value, expected);
    }
}
