use serde::{Deserialize, Serialize};
use ssi_json_ld::LangString;

use crate::v2::data_model;

/// International string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InternationalString {
    String(String),
    LanguageValue(LangString),
    LanguageMap(Vec<LangString>),
}

impl data_model::AnyInternationalString for InternationalString {
    fn default_value(&self) -> Option<data_model::LanguageValueRef> {
        match self {
            Self::String(s) => s.default_value(),
            Self::LanguageValue(v) => v.default_value(),
            Self::LanguageMap(_) => None,
        }
    }

    fn get_language(
        &self,
        lang: &ssi_json_ld::syntax::LangTag,
    ) -> Option<data_model::LanguageValueRef> {
        match self {
            Self::String(_) => None,
            Self::LanguageValue(v) => {
                if let Some(tag) = v.language() {
                    if tag.as_str() == lang.as_str() {
                        return Some(v.into());
                    }
                }

                None
            }
            Self::LanguageMap(values) => values.iter().find_map(|v| {
                if let Some(tag) = v.language() {
                    if tag.as_str() == lang.as_str() {
                        return Some(v.into());
                    }
                }

                None
            }),
        }
    }
}

impl From<String> for InternationalString {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<LangString> for InternationalString {
    fn from(value: LangString) -> Self {
        Self::LanguageValue(value)
    }
}
