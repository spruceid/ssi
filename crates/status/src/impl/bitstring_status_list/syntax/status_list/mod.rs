use iref::UriBuf;
use serde::{Deserialize, Serialize};

mod credential;
pub use credential::*;

use crate::bitstring_status_list::{EncodedList, StatusList, StatusPurpose, TimeToLive};

pub const BITSTRING_STATUS_LIST_TYPE: &str = "BitstringStatusList";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct BitstringStatusList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Status purpose.
    pub status_purpose: StatusPurpose,

    /// Encoded status list.
    pub encoded_list: EncodedList,

    /// Time to live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<TimeToLive>,
}

impl BitstringStatusList {
    pub fn new(
        id: Option<UriBuf>,
        status_purpose: StatusPurpose,
        encoded_list: EncodedList,
        ttl: TimeToLive,
    ) -> Self {
        Self {
            id,
            status_purpose,
            encoded_list,
            ttl: if ttl.is_default() { None } else { Some(ttl) },
        }
    }

    pub fn decode(&self) -> Result<StatusList, DecodeError> {
        let bytes = self.encoded_list.decode(None)?;
        Ok(StatusList::from_bytes(bytes, self.ttl.unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::BitstringStatusList;
    use crate::bitstring_status_list::{EncodedList, StatusPurpose, TimeToLive};

    const STATUS_LIST: &str = r#"{
        "id": "https://example.com/status/3#list",
        "type": "BitstringStatusList",
        "ttl": 500,
        "statusPurpose": "revocation",
        "encodedList": "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
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
            ttl: Some(TimeToLive(500)),
            status_purpose: StatusPurpose::Revocation,
            encoded_list: EncodedList::new(
                "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA".to_owned(),
            ),
        };

        let value = serde_json::to_value(status_list).unwrap();
        assert_eq!(value, expected);
    }
}
