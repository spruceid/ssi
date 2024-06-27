use ssi_json_ld::{syntax::LangTag, Direction, LangString, LenientLangTag};

pub struct LanguageValue<'a> {
    pub value: &'a str,
    pub language: Option<&'a LangTag>,
    pub direction: Option<Direction>,
}

impl<'a> From<&'a LangString> for LanguageValue<'a> {
    fn from(value: &'a LangString) -> Self {
        LanguageValue {
            value: value.as_str(),
            language: value.language().and_then(LenientLangTag::as_well_formed),
            direction: value.direction(),
        }
    }
}

pub trait InternationalString {
    fn default_value(&self) -> Option<LanguageValue>;
}

impl InternationalString for std::convert::Infallible {
    fn default_value(&self) -> Option<LanguageValue> {
        unreachable!()
    }
}
