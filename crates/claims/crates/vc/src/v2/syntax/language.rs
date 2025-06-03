use serde::{Deserialize, Serialize};
use ssi_json_ld::LangString;

use crate::v2::data_model;

/// International string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InternationalString {
    String(String),
    LanguageValue(LangString),
    LanguageMap(Vec<LangString>),
}

impl data_model::InternationalString for InternationalString {
    fn default_value(&self) -> Option<data_model::LanguageValue> {
        match self {
            Self::String(s) => s.default_value(),
            Self::LanguageValue(v) => v.default_value(),
            Self::LanguageMap(_) => None,
        }
    }
}
