use std::collections::BTreeMap;

use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    #[serde(rename = "type")]
    pub type_: Vec<String>,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::Evidence for Evidence {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    fn type_(&self) -> &[String] {
        &self.type_
    }
}
