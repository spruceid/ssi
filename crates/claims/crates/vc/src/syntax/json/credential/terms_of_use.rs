use std::collections::BTreeMap;

use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, json_syntax::Value>>,
}

impl crate::TermsOfUse for TermsOfUse {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }

    fn type_(&self) -> &str {
        &self.type_
    }
}
