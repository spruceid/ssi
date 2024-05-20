use json_ld::LangString;

/// International string.
pub enum MultiLangString {
    String(String),
    LanguageValue(LangString),
    LanguageMap(Vec<LangString>),
}
