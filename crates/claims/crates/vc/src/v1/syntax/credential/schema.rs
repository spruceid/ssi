use std::collections::BTreeMap;

use iref::UriBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}
