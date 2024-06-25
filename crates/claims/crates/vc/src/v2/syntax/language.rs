use crate::v2::LanguageValue;
use ssi_json_ld::LangString;

/// International string.
pub enum InternationalString {
    String(String),
    LanguageValue(LangString),
    LanguageMap(Vec<LangString>),
}

impl crate::v2::InternationalString for InternationalString {
    fn default_value(&self) -> Option<LanguageValue> {
        match self {
            Self::String(s) => Some(LanguageValue {
                value: s,
                language: None,
                direction: None,
            }),
            Self::LanguageValue(l) => Some(l.into()),
            Self::LanguageMap(_) => None,
        }
    }
}
