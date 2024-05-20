use json_ld::{syntax::LangTag, Direction};

pub struct LanguageValue<'a> {
    pub value: &'a str,
    pub language: Option<&'a LangTag>,
    pub direction: Option<Direction>,
}

pub trait InternationalString {
    fn default_value(&self) -> Option<LanguageValue>;
}

impl InternationalString for std::convert::Infallible {
    fn default_value(&self) -> Option<LanguageValue> {
        unreachable!()
    }
}
