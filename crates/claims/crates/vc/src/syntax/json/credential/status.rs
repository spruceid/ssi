use std::collections::BTreeMap;

use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::CredentialStatus for Status {
    fn id(&self) -> &Uri {
        &self.id
    }
}
