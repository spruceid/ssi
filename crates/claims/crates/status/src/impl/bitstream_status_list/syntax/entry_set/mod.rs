use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

mod credential;
pub use credential::*;

use crate::{bitstream_status_list::StatusPurpose, StatusMapEntry};

pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";

/// Bitstring status list entry.
///
/// References a particular entry of a status list, for a given status purpose.
/// It is the type of the `credentialStatus` property of a Verifiable
/// Credential.
///
/// See: <https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry>
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
    /// Optional identifier for the status list entry.
    ///
    /// Identifies the status information associated with the verifiable
    /// credential. Must *not* be the URL of the status list.
    id: Option<UriBuf>,

    /// `BitstringStatusListEntry` type.
    #[serde(rename = "type")]
    type_: BitstringStatusListEntryType,

    /// Purpose of the status entry.
    status_purpose: StatusPurpose,

    /// URL to a `BitstringStatusListCredential` verifiable credential.
    status_list_credential: UriBuf,

    /// Arbitrary size integer greater than or equal to 0, encoded as a string
    /// in base 10.
    #[serde(with = "base10_nat_string")]
    status_list_index: usize,
}

impl StatusMapEntry for BitstringStatusListEntry {
    type Key = usize;

    fn status_list_url(&self) -> &Uri {
        &self.status_list_credential
    }

    fn key(&self) -> Self::Key {
        self.status_list_index
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitstringStatusListEntryType;

impl Serialize for BitstringStatusListEntryType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BITSTRING_STATUS_LIST_ENTRY_TYPE.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BitstringStatusListEntryType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let type_ = String::deserialize(deserializer)?;
        if type_ == BITSTRING_STATUS_LIST_ENTRY_TYPE {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected `BitstringStatusListEntry` type",
            ))
        }
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
