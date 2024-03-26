use std::collections::BTreeMap;

use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::RefreshService for RefreshService {
    fn id(&self) -> &Uri {
        &self.id
    }

    fn type_(&self) -> &str {
        &self.type_
    }
}
