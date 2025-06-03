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

impl<T: ?Sized + InternationalString> InternationalString for &T {
    fn default_value(&self) -> Option<LanguageValue> {
        T::default_value(*self)
    }
}

impl InternationalString for str {
    fn default_value(&self) -> Option<LanguageValue> {
        Some(LanguageValue {
            value: self,
            language: None,
            direction: None,
        })
    }
}

impl InternationalString for String {
    fn default_value(&self) -> Option<LanguageValue> {
        self.as_str().default_value()
    }
}

impl InternationalString for LangString {
    fn default_value(&self) -> Option<LanguageValue> {
        Some(LanguageValue::from(self))
    }
}
