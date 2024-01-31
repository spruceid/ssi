use std::collections::BTreeMap;

use iref::{IriBuf, UriBuf};

/// Generic verification method.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenericVerificationMethod {
    /// Identifier.
    pub id: IriBuf,

    /// Type name.
    #[serde(rename = "type")]
    pub type_: String,

    /// Method controller.
    pub controller: UriBuf,

    /// Other properties.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}
