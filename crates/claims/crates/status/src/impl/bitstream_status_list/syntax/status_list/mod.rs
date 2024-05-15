use iref::UriBuf;
use serde::{Deserialize, Serialize};

mod credential;
pub use credential::*;

use crate::bitstream_status_list::{
    EncodedList, StatusList, StatusMessage, StatusPurpose, StatusSize, TimeToLive,
};

pub const BITSTRING_STATUS_LIST_TYPE: &str = "BitstringStatusList";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// `BitstringStatusList` type.
    #[serde(rename = "type")]
    pub type_: BitstringStatusListType,

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
            type_: BitstringStatusListType,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitstringStatusListType;

impl Serialize for BitstringStatusListType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BITSTRING_STATUS_LIST_TYPE.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BitstringStatusListType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let type_ = String::deserialize(deserializer)?;
        if type_ == BITSTRING_STATUS_LIST_TYPE {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected `BitstringStatusList` type",
            ))
        }
    }
}
