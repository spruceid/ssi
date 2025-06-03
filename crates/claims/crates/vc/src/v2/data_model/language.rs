use ssi_json_ld::{syntax::LangTag, Direction, LangString, LenientLangTag};

pub struct LanguageValueRef<'a> {
    pub value: &'a str,
    pub language: Option<&'a LangTag>,
    pub direction: Option<Direction>,
}

impl<'a> From<&'a LangString> for LanguageValueRef<'a> {
    fn from(value: &'a LangString) -> Self {
        LanguageValueRef {
            value: value.as_str(),
            language: value.language().and_then(LenientLangTag::as_well_formed),
            direction: value.direction(),
        }
    }
}

pub trait AnyInternationalString {
    fn default_value(&self) -> Option<LanguageValueRef>;

    fn get_language(&self, _lang: &LangTag) -> Option<LanguageValueRef> {
        None
    }

    fn get_language_or_default(&self, lang: &LangTag) -> Option<LanguageValueRef> {
        self.get_language(lang).or_else(|| self.default_value())
    }
}

impl<T: ?Sized + AnyInternationalString> AnyInternationalString for &T {
    fn default_value(&self) -> Option<LanguageValueRef> {
        T::default_value(*self)
    }
}

impl AnyInternationalString for str {
    fn default_value(&self) -> Option<LanguageValueRef> {
        Some(LanguageValueRef {
            value: self,
            language: None,
            direction: None,
        })
    }
}

impl AnyInternationalString for String {
    fn default_value(&self) -> Option<LanguageValueRef> {
        self.as_str().default_value()
    }
}

impl AnyInternationalString for LangString {
    fn default_value(&self) -> Option<LanguageValueRef> {
        Some(LanguageValueRef::from(self))
    }
}
